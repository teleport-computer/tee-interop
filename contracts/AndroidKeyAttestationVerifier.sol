// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";

/// @title AndroidKeyAttestationVerifier
/// @notice IVerifier adapter for Android Key Attestation (Pixel 6+ Titan M2 / StrongBox).
///
/// The proof is the device-produced cert chain (leaf with attestation extension,
/// intermediates, root) plus the parsed extension data. The verifier:
///   1. Validates the chain against an owner-pinned set of Google attestation roots.
///   2. Parses the Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
///   3. Enforces policy: verifiedBootState == Verified, deviceLocked == true.
///   4. Returns:
///        codeId   = sha256 of attestationApplicationId.signingCert     (identifies the app)
///        pubkey   = leaf's subject public key                          (the per-node key)
///        userData = the attestation challenge                          (replay-protection)
///
/// On-chain X.509 chain verification (ECDSA-P256/P384 + RSA-4096 PKCS#1v1.5)
/// is intentionally stubbed in this skeleton. See `_verifyChain` for the contract
/// the host-side proof builder maintains, and the accompanying tests for the
/// FFI-bridged reference implementation in `tools/android_keyattest_proof.py`.
contract AndroidKeyAttestationVerifier is IVerifier {
    /// SHA-256 fingerprint of each pinned Google attestation root certificate.
    /// Pinned in storage so the owner can rotate as Google rotates roots.
    mapping(bytes32 => bool) public allowedRootFingerprints;

    /// Optional allow-list of app signing-cert SHA-256s. If `requireAppAllowlist`
    /// is true, only proofs whose attestationApplicationId.signingCert matches
    /// an entry here will verify. Useful for pinning a specific signed APK.
    mapping(bytes32 => bool) public allowedAppCertHashes;
    bool public requireAppAllowlist;

    /// Minimum osPatchLevel (YYYYMM) the proof must declare. 0 disables.
    uint32 public minOsPatchLevel;

    /// Allow-list of accepted AVB vbmeta digests (verifiedBootHash). Each entry
    /// is the measurement of one exact OS+app image. Like an MRENCLAVE set: the
    /// owner adds the next image's digest before a rollout and retires the old
    /// one afterwards, so multiple legitimate versions can be live at once.
    mapping(bytes32 => bool) public allowedBootHashes;

    address public owner;

    /// When true this is an explicitly-marked TESTNET instance: it still runs
    /// the full validation path (genuine chain, StrongBox, challenge binding,
    /// verifiedBootHash) but RECORDS an unlocked / non-green boot state instead
    /// of reverting. The true posture is packed into the returned userData so
    /// the on-chain member record cannot be mistaken for a locked device.
    /// A production instance sets this false and rejects unlocked devices.
    bool public immutable testnetMode;

    struct AndroidProof {
        /// The full cert chain, leaf-first. Each entry is the DER encoding
        /// of one X.509 certificate. `certs[0]` is the leaf carrying the
        /// Android Key Attestation extension.
        bytes[] certs;
        /// The challenge bytes that the verifier expects to find at
        /// `KeyDescription.attestationChallenge` in the leaf's extension.
        bytes challenge;
        /// Caller-supplied parse of the leaf's KeyDescription. These MUST
        /// match what an on-chain re-parse of `certs[0]` would yield once
        /// X.509 + extension parsing lands. Until then, treated as untrusted
        /// hints that the host-side proof builder filled in and the test
        /// harness validates via FFI.
        ParsedKeyDescription parsed;
    }

    /// Subset of the Android KeyDescription struct needed for policy decisions.
    /// Names match the AOSP spec at
    /// https://source.android.com/docs/security/features/keystore/attestation
    struct ParsedKeyDescription {
        /// 0 = Software, 1 = TrustedEnvironment, 2 = StrongBox.
        uint8 attestationSecurityLevel;
        /// Same encoding as above; should equal attestationSecurityLevel
        /// for hardware-backed keys.
        uint8 keyMintSecurityLevel;
        /// 0 = Verified, 1 = SelfSigned, 2 = Unverified, 3 = Failed.
        uint8 verifiedBootState;
        bool deviceLocked;
        /// First 32 bytes of the verifiedBootHash (full digest of the AVB
        /// vbmeta partition tree). Useful for code-identity policy.
        bytes32 verifiedBootHash;
        /// Boot-key AVB pinned in the leaf — empty / zero for Google root key.
        bytes32 verifiedBootKey;
        /// sha256 of the package signing cert (taken from
        /// attestationApplicationId.signature_digests[0]).
        bytes32 appCertSha256;
        /// YYYYMM packed into a uint32 (e.g. 202604).
        uint32 osPatchLevel;
        /// Leaf's subject public key, X9.62 uncompressed (0x04 || X || Y) for EC.
        bytes leafPubkey;
    }

    event RootAllowed(bytes32 indexed sha256Fingerprint);
    event RootRemoved(bytes32 indexed sha256Fingerprint);
    event AppCertAllowed(bytes32 indexed certSha256);
    event AppCertRemoved(bytes32 indexed certSha256);
    event AppAllowlistToggled(bool required);
    event MinOsPatchLevelSet(uint32 level);
    event BootHashAllowed(bytes32 indexed verifiedBootHash);
    event BootHashRemoved(bytes32 indexed verifiedBootHash);

    error NotOwner();
    error EmptyChain();
    error RootNotAllowed(bytes32 sha256Fingerprint);
    error BadChain();
    error VerifiedBootStateRejected(uint8 state);
    error DeviceNotLocked();
    error AppCertNotAllowed(bytes32 certSha256);
    error OsPatchLevelTooLow(uint32 got, uint32 want);
    error ChallengeMismatch();
    error VerifiedBootHashMismatch(bytes32 got, bytes32 want);
    error BootHashNotAllowed(bytes32 verifiedBootHash);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    constructor(bytes32[] memory initialRoots, bool _testnetMode) {
        owner = msg.sender;
        testnetMode = _testnetMode;
        for (uint256 i = 0; i < initialRoots.length; i++) {
            allowedRootFingerprints[initialRoots[i]] = true;
            emit RootAllowed(initialRoots[i]);
        }
    }

    // --- Admin ---

    function addRoot(bytes32 sha256Fingerprint) external onlyOwner {
        allowedRootFingerprints[sha256Fingerprint] = true;
        emit RootAllowed(sha256Fingerprint);
    }

    function removeRoot(bytes32 sha256Fingerprint) external onlyOwner {
        allowedRootFingerprints[sha256Fingerprint] = false;
        emit RootRemoved(sha256Fingerprint);
    }

    function addAllowedAppCert(bytes32 certSha256) external onlyOwner {
        allowedAppCertHashes[certSha256] = true;
        emit AppCertAllowed(certSha256);
    }

    function removeAllowedAppCert(bytes32 certSha256) external onlyOwner {
        allowedAppCertHashes[certSha256] = false;
        emit AppCertRemoved(certSha256);
    }

    function setRequireAppAllowlist(bool required) external onlyOwner {
        requireAppAllowlist = required;
        emit AppAllowlistToggled(required);
    }

    function setMinOsPatchLevel(uint32 level) external onlyOwner {
        minOsPatchLevel = level;
        emit MinOsPatchLevelSet(level);
    }

    function addAllowedBootHash(bytes32 verifiedBootHash) external onlyOwner {
        allowedBootHashes[verifiedBootHash] = true;
        emit BootHashAllowed(verifiedBootHash);
    }

    function removeAllowedBootHash(bytes32 verifiedBootHash) external onlyOwner {
        allowedBootHashes[verifiedBootHash] = false;
        emit BootHashRemoved(verifiedBootHash);
    }

    // --- IVerifier ---

    function verify(bytes calldata proof)
        external
        view
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return _verifyProof(proof, bytes32(0));
    }

    function verifyAndCache(bytes calldata proof)
        external
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return _verifyProof(proof, bytes32(0));
    }

    /// @notice Pin the exact OS image. `expectedVerifiedBootHash` is the AVB
    /// vbmeta digest; via dm-verity it covers the whole system partition,
    /// including an app baked into /system/priv-app. A device flashed with a
    /// custom AVB key reports SelfSigned (yellow) boot state — so this path
    /// accepts yellow and derives all trust from the pinned digest, not from
    /// Google's factory key. The returned codeId is the vbmeta digest itself:
    /// the identity of the OS+app image actually measured by Titan M2.
    function verifyWithBootHash(bytes calldata proof, bytes32 expectedVerifiedBootHash)
        external
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        if (expectedVerifiedBootHash == bytes32(0)) revert VerifiedBootHashMismatch(bytes32(0), bytes32(0));
        return _verifyProof(proof, expectedVerifiedBootHash);
    }

    /// @notice Self-rooted appliance path against the owner-maintained allow-list.
    /// The proof's verifiedBootHash must be a currently-allowed image digest.
    /// Returns codeId = the matched vbmeta digest (the OS+app code identity).
    function verifyAllowlisted(bytes calldata proof)
        external
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        bytes32 vbh = abi.decode(proof, (AndroidProof)).parsed.verifiedBootHash;
        if (!allowedBootHashes[vbh]) revert BootHashNotAllowed(vbh);
        return _verifyProof(proof, vbh);
    }

    function _verifyProof(bytes calldata proof, bytes32 expectedVerifiedBootHash)
        internal
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        AndroidProof memory p = abi.decode(proof, (AndroidProof));

        // 1. Chain non-empty
        if (p.certs.length == 0) revert EmptyChain();

        // 2. Top of chain matches a pinned root fingerprint
        bytes32 rootFp = sha256(p.certs[p.certs.length - 1]);
        if (!allowedRootFingerprints[rootFp]) revert RootNotAllowed(rootFp);

        // 3. Chain link signatures
        // TODO(skeleton): ECDSA-P256 / ECDSA-P384 / RSA-PKCS1v15 verification of
        // each link. Pixel-6-era chains: leaf and intermediates are P-256, root
        // is P-256 or P-384 depending on which of Google's two roots is in use.
        // The Python reference verifier in tools/android_keyattest_proof.py
        // performs this check off-chain; on-chain ports of these primitives
        // exist (e.g. automata-dcap-attestation, ZeroPool's ecrecover-p256)
        // and slot in here without touching the surrounding logic.
        if (!_verifyChain(p.certs)) revert BadChain();

        // 4. Extension-derived policy
        ParsedKeyDescription memory kd = p.parsed;

        if (expectedVerifiedBootHash == bytes32(0)) {
            // OEM-rooted path: require Verified (green) — Google/OEM factory key.
            if (kd.verifiedBootState != 0 && !testnetMode) revert VerifiedBootStateRejected(kd.verifiedBootState);
        } else {
            // Self-rooted appliance path. Trust model is MRENCLAVE, NOT MRSIGNER:
            // the ONLY anchors are deviceLocked (below) + verifiedBootHash on the
            // allow-list. The signing key (verifiedBootKey) is never read — a
            // custom AVB key reports SelfSigned (yellow) and that is fine.
            //
            // NOTE: the verifiedBootState <= 1 line is a VESTIGIAL, redundant
            // guard — deviceLocked == true already implies state is green(0) or
            // yellow(1) (orange/red come with unlocked/failed boots). It is kept
            // only as defense-in-depth and is NOT a trust input; do not read it
            // as "we care which key signed." Dropping it would not weaken the
            // model. Left in to avoid a redeploy; see docs/android for the model.
            if (kd.verifiedBootState > 1 && !testnetMode) revert VerifiedBootStateRejected(kd.verifiedBootState);
            // OS binding is NEVER relaxed: the measured image must match the pin.
            if (kd.verifiedBootHash != expectedVerifiedBootHash) {
                revert VerifiedBootHashMismatch(kd.verifiedBootHash, expectedVerifiedBootHash);
            }
        }
        if (!kd.deviceLocked && !testnetMode) revert DeviceNotLocked();

        if (requireAppAllowlist && !allowedAppCertHashes[kd.appCertSha256]) {
            revert AppCertNotAllowed(kd.appCertSha256);
        }

        if (kd.osPatchLevel < minOsPatchLevel) {
            revert OsPatchLevelTooLow(kd.osPatchLevel, minOsPatchLevel);
        }

        // 5. Challenge in proof matches challenge declared in leaf extension.
        // TODO(skeleton): once on-chain extension parsing is in place, re-derive
        // the challenge from p.certs[0] and compare against p.challenge. For
        // now, the host-side proof builder asserts this equality, and tests
        // exercise both equal- and mismatching-challenge cases.
        if (!_challengeMatchesLeaf(p)) revert ChallengeMismatch();

        // Code identity: the OS+app image digest for the pinned path; the app
        // signing-cert hash for the OEM-rooted path.
        codeId = expectedVerifiedBootHash == bytes32(0) ? kd.appCertSha256 : kd.verifiedBootHash;
        // Production: userData = challenge only. Testnet: also commit the true,
        // possibly-downgraded security posture so the member record is explicit.
        userData = testnetMode
            ? abi.encode(p.challenge, kd.verifiedBootHash, kd.appCertSha256, kd.deviceLocked, kd.verifiedBootState)
            : p.challenge;
        return (codeId, kd.leafPubkey, userData);
    }

    /// @dev Stubbed. See top-level comment.
    function _verifyChain(bytes[] memory) internal pure returns (bool) {
        return true;
    }

    /// @dev Stubbed. See top-level comment.
    function _challengeMatchesLeaf(AndroidProof memory) internal pure returns (bool) {
        return true;
    }
}
