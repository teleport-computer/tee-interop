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

    address public owner;

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

    error NotOwner();
    error EmptyChain();
    error RootNotAllowed(bytes32 sha256Fingerprint);
    error BadChain();
    error VerifiedBootStateRejected(uint8 state);
    error DeviceNotLocked();
    error AppCertNotAllowed(bytes32 certSha256);
    error OsPatchLevelTooLow(uint32 got, uint32 want);
    error ChallengeMismatch();

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    constructor(bytes32[] memory initialRoots) {
        owner = msg.sender;
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

    // --- IVerifier ---

    function verify(bytes calldata proof)
        external
        view
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return _verifyProof(proof);
    }

    function verifyAndCache(bytes calldata proof)
        external
        override
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        return _verifyProof(proof);
    }

    function _verifyProof(bytes calldata proof)
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

        if (kd.verifiedBootState != 0) revert VerifiedBootStateRejected(kd.verifiedBootState);
        if (!kd.deviceLocked) revert DeviceNotLocked();

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

        return (kd.appCertSha256, kd.leafPubkey, p.challenge);
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
