// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";

/// @title SilabsVerifier
/// @notice IVerifier adapter for Silicon Labs Secure Vault High (Series 2 SVH
///         and Series 3 SiXG301) device attestation.
///
/// The on-die Secure Element signs a PSA Initial Attestation Token (EAT,
/// COSE_Sign1 / ES256) with its per-device P-256 attestation key, provisioned at
/// Silicon Labs manufacturing. The off-chain host (tools/silabs/build_proof.py)
/// verifies the device-identity X.509 chain
///   SE-leaf (EUI) -> Batch -> Factory -> Device Root CA
/// against Silicon Labs' published root (ca.silabs.com) and pins that root's
/// SHA-256 fingerprint into this proof. On-chain the verifier:
///   1. secp256r1-verifies (r,s) over the COSE Sig_structure digest with the
///      device pubkey, via the RIP-7212 precompile at 0x100.
///   2. Requires the Silicon Labs Device Root CA fingerprint to be allowlisted.
///   3. Enforces the dev-mode policy (see below).
///   4. Returns:
///        codeId   = measurement = SHA-256 from EAT claim -75006 (Software
///                   Components): the secure-booted application (`ARoT`) when
///                   secure boot is enabled, else the SE PRoT firmware hash.
///        pubkey   = devicePubkeyXY (the per-device P-256 attestation key)
///        userData = abi.encode(nonce, secureBoot) (challenge -75008 + posture)
///
/// Dev mode: a SiLabs part ships with secure boot OFF (no irreversible OTP burn),
/// so its EAT carries no `ARoT` app measurement — only the SE `PRoT` firmware hash.
/// `secureBoot` is read from the signed token (ARoT present <=> secure boot on) by
/// the off-chain builder. When secureBoot is false the device is NOT code-bound;
/// such proofs are rejected unless the owner has explicitly opted in via
/// `acceptDevMode` (default off — secure by default). This lets a testnet accept
/// un-provisioned devices on purpose while production stays strict; the same proof
/// path yields the real `ARoT` app measurement once secure boot is provisioned.
///
/// Mirrors Stm32DuaVerifier (same PSA EAT / COSE_Sign1 / ES256 shape). SiLabs
/// nonces are 32/48/64 bytes, so `nonce` is dynamic `bytes` rather than bytes32.
///
/// Trust boundary: the device signature is re-checked in-EVM; `measurement` and
/// `nonce` are extracted from the signed payload off-chain (same as the STM32
/// adapter). A future variant can re-derive the digest from the raw payload and
/// CBOR-extract the claims on-chain for full trustlessness.
contract SilabsVerifier is IVerifier {
    /// secp256r1 verification precompile (RIP-7212).
    address constant P256_VERIFY = address(0x100);

    /// SHA-256 fingerprints of pinned Silicon Labs Device Root CA certificates.
    mapping(bytes32 => bool) public allowedRootFingerprints;

    address public owner;

    /// When true, attestations from devices without secure boot (dev mode, no
    /// `ARoT` code measurement) are tolerated. Default false (secure by default).
    bool public acceptDevMode;

    event RootAllowed(bytes32 indexed sha256Fingerprint);
    event RootRemoved(bytes32 indexed sha256Fingerprint);
    event AcceptDevModeSet(bool accepted);

    error NotOwner();
    error RootNotAllowed(bytes32 sha256Fingerprint);
    error InvalidSignature();
    error DevModeNotAccepted();

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

    function _verifyProof(bytes calldata proof)
        internal
        view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        (
            bytes memory devicePubkeyXY,
            bytes32 cosePayloadDigest,
            bytes32 r,
            bytes32 s,
            bytes32 measurement,
            bytes memory nonce,
            bool secureBoot,
            bytes32 silabsRootFingerprint
        ) = abi.decode(proof, (bytes, bytes32, bytes32, bytes32, bytes32, bytes, bool, bytes32));

        if (!allowedRootFingerprints[silabsRootFingerprint]) revert RootNotAllowed(silabsRootFingerprint);
        if (!secureBoot && !acceptDevMode) revert DevModeNotAccepted();

        // devicePubkeyXY is X9.62 uncompressed (0x04 || X[32] || Y[32]).
        (bytes32 qx, bytes32 qy) = _splitPubkey(devicePubkeyXY);

        if (!_p256Verify(cosePayloadDigest, r, s, qx, qy)) revert InvalidSignature();

        return (measurement, devicePubkeyXY, abi.encode(nonce, secureBoot));
    }

    function _splitPubkey(bytes memory pk) internal pure returns (bytes32 qx, bytes32 qy) {
        if (pk.length != 65 || pk[0] != 0x04) revert InvalidSignature();
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
