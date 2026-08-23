// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";

/// @title Stm32SecureManagerVerifier
/// @notice IVerifier adapter for STM32H573 running ST's closed STM32Trustee
///         Secure Manager (SESIP/PSA L3).
///
/// The initial-attestation key (IAK) lives inside ST's Secure Manager at PSA
/// isolation level 3. The operator holds the application signing key but is
/// locked out of the secure domain: they can boot code, but cannot forge its
/// measurement. SMuRoT measures the non-secure application and SM signs an EAT
/// (COSE_Sign1 / ES256) carrying that hash in PSA claim -75006 as the `NSPE`
/// software component.
///
/// ## Why this adapter verifies the whole chain on-chain
///
/// SilabsVerifier pins a root *fingerprint* and trusts the off-chain builder to
/// have walked SE -> Batch -> Factory -> Device Root (depth 4). The STM32 DUA
/// chain is only **depth 2** — the initial-attestation leaf is signed directly by
/// a self-signed CA — so the entire path to the root is a single P-256 check.
/// This verifier therefore does two chained RIP-7212 verifications and never has
/// to trust that anyone walked a chain:
///
///   1. `leafR/leafS` over `leafTbsDigest` under the pinned ST CA key
///      => the IAK public key really was issued by ST.
///   2. `eatR/eatS` over `cosePayloadDigest` under that IAK
///      => the token really was signed by that device's Secure Manager.
///
/// ## The anchor
///
/// ST delivers the initial-attestation CA certificate under licence, so unlike
/// Silicon Labs there is no published root to pin. The pinned key is instead
/// *determined*: a P-256 signature plus its message pins the signer to two
/// candidates, and intersecting the candidate pairs from two independent leaves
/// leaves exactly one key. The two leaves used were a die we own and the example
/// certificate ST printed in UM3254 Rev 8 Figure 7 — so both halves are
/// externally reproducible by anyone with the (public) user manual and any
/// STM32H573. The pinned value is the CA *public key*, which is all a verifier
/// needs; the signed CA certificate was never the requirement.
///
/// ## Lifecycle policy
///
/// PSA claim -75002 exposes the product state. The `NSPE` measurement is only
/// trustworthy once the part reaches PRODUCT_STATE Closed, which reports
/// lifecycle `0x3000` SECURED. A part still in TZ-Closed reports `0x4000`
/// NON_PSA_ROT_DEBUG and is not code-bound for production purposes; such proofs
/// are rejected unless the owner opts in via `acceptDevMode` (default off).
/// Unlike the Silicon Labs OTP burn, reaching Closed on the H573 is reversible —
/// a debug-authenticated full regression returns the part to Open, and only
/// PRODUCT_STATE Locked is final.
///
/// ## Trust boundary
///
/// The two signatures are re-checked in-EVM and the chain to the pinned root is
/// fully covered. Still off-chain: `measurement`, `nonce` and `lifecycle` are
/// CBOR-extracted from the signed payload by the builder rather than parsed
/// on-chain. The payload digest binds them, so a mismatch cannot be forged
/// without breaking the signature, but a caller could in principle mislabel
/// which claim is which. Parsing CBOR on-chain would close that last gap.
contract Stm32SecureManagerVerifier is IVerifier {
    /// secp256r1 verification precompile (RIP-7212).
    address constant P256_VERIFY = address(0x100);

    /// PSA security lifecycle value meaning SECURED (ST PRODUCT_STATE Closed).
    uint32 constant LIFECYCLE_SECURED = 0x3000;

    /// SHA-256 fingerprints over the X9.62 uncompressed encoding of pinned ST
    /// initial-attestation CA public keys.
    mapping(bytes32 => bool) public allowedCaFingerprints;

    address public owner;

    /// When true, tokens from parts not yet in SECURED lifecycle are tolerated.
    bool public acceptDevMode;

    event CaAllowed(bytes32 indexed sha256Fingerprint);
    event CaRemoved(bytes32 indexed sha256Fingerprint);
    event AcceptDevModeSet(bool accepted);

    error NotOwner();
    error CaNotAllowed(bytes32 sha256Fingerprint);
    error InvalidCertSignature();
    error InvalidTokenSignature();
    error NotSecured(uint32 lifecycle);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }

    constructor(bytes32[] memory initialCas) {
        owner = msg.sender;
        for (uint256 i = 0; i < initialCas.length; i++) {
            allowedCaFingerprints[initialCas[i]] = true;
            emit CaAllowed(initialCas[i]);
        }
    }

    // --- Admin ---

    function addCa(bytes32 sha256Fingerprint) external onlyOwner {
        allowedCaFingerprints[sha256Fingerprint] = true;
        emit CaAllowed(sha256Fingerprint);
    }

    function removeCa(bytes32 sha256Fingerprint) external onlyOwner {
        allowedCaFingerprints[sha256Fingerprint] = false;
        emit CaRemoved(sha256Fingerprint);
    }

    function setAcceptDevMode(bool accepted) external onlyOwner {
        acceptDevMode = accepted;
        emit AcceptDevModeSet(accepted);
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

    /// Signatures travel as packed r‖s (64 bytes) to keep the tuple shallow.
    struct Proof {
        bytes stCaPubkeyXY;      // X9.62 uncompressed ST init-attest CA key
        bytes iakPubkeyXY;       // X9.62 uncompressed device IAK, from the leaf
        bytes32 leafTbsDigest;   // SHA-256 of the leaf's tbsCertificate
        bytes leafSig;           // r‖s of the CA over the leaf
        bytes32 cosePayloadDigest; // SHA-256 of the COSE Sig_structure
        bytes eatSig;            // r‖s of the IAK over the token
        bytes32 measurement;     // -75006 NSPE
        bytes nonce;             // -75008
        uint32 lifecycle;        // -75002
    }

    function _verifyProof(bytes calldata proof)
        internal
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        Proof memory p = abi.decode(proof, (Proof));

        bytes32 caFingerprint = sha256(p.stCaPubkeyXY);
        if (!allowedCaFingerprints[caFingerprint]) revert CaNotAllowed(caFingerprint);
        if (p.lifecycle != LIFECYCLE_SECURED && !acceptDevMode) revert NotSecured(p.lifecycle);

        // 1. The IAK really was certified by ST (depth-2 chain, one hop to root).
        if (!_verifyOver(p.leafTbsDigest, p.leafSig, p.stCaPubkeyXY)) revert InvalidCertSignature();

        // 2. The token really was signed by that device's Secure Manager.
        if (!_verifyOver(p.cosePayloadDigest, p.eatSig, p.iakPubkeyXY)) revert InvalidTokenSignature();

        return (p.measurement, p.iakPubkeyXY, abi.encode(p.nonce, p.lifecycle));
    }

    function _verifyOver(bytes32 digest, bytes memory sig, bytes memory pk)
        internal
        view
        returns (bool)
    {
        require(sig.length == 64, "bad sig");
        (bytes32 qx, bytes32 qy) = _splitPubkey(pk);
        bytes32 r;
        bytes32 s;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
        }
        return _p256Verify(digest, r, s, qx, qy);
    }

    function _splitPubkey(bytes memory pk) internal pure returns (bytes32 qx, bytes32 qy) {
        require(pk.length == 65 && pk[0] == 0x04, "bad pubkey");
        assembly {
            qx := mload(add(pk, 33))
            qy := mload(add(pk, 65))
        }
    }

    function _p256Verify(bytes32 hash, bytes32 r, bytes32 s, bytes32 qx, bytes32 qy)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory out) = P256_VERIFY.staticcall(abi.encodePacked(hash, r, s, qx, qy));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }
}
