// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";

interface ITEEBridgeView {
    function getMember(bytes32 memberId) external view returns (
        bytes32 codeId, address verifier, bytes memory pubkey, bytes memory userData, uint256 registeredAt
    );
}

/// @title TinfoilAdapter (TEE Proof)
/// @notice Implements the "TEE Proof" pattern from ERC-733 §C: heavy attestation
///         verification (SEV-SNP / TDX cert chains, Sigstore bundle, dm-verity
///         root) is offloaded to an off-chain TEE running tinfoil-go. That TEE
///         signs the verified envelope with its encumbered secp256k1 key.
///
///         The signer's trustworthiness is rooted in TEEBridge itself: the
///         signer must already be a registered member whose codeId matches the
///         canonical tinfoil-go-verifier image. This composes the bridge with
///         itself — DstackVerifier (or any IVerifier) bootstraps the verifier
///         enclave; that enclave then bootstraps Tinfoil-attested targets.
///
///         Trust assumption: blockchain + TEE (per ERC-733 §C). Cost:
///         single ecrecover + one storage read (~150K gas).
contract TinfoilAdapter is IVerifier {
    ITEEBridgeView public immutable bridge;
    bytes32 public immutable verifierCodeId;

    /// @notice Tinfoil attestation envelope, signed by an off-chain TEE running tinfoil-go.
    struct TinfoilProof {
        bytes32 codeId;
        bytes32 sigstoreDigest;
        bytes32 dmVerityRoot;
        bytes derivedCompressedPubkey;
        bytes userData;
        string domain;
        bytes signerCompressedPubkey;
        bytes signerSig;
    }

    error VerifierNotRegistered();
    error VerifierWrongCode();
    error InvalidTinfoilSignature();

    constructor(address _bridge, bytes32 _verifierCodeId) {
        bridge = ITEEBridgeView(_bridge);
        verifierCodeId = _verifierCodeId;
    }

    function verify(bytes calldata proof) external view override returns (bytes32 codeId, bytes memory pubkey, bytes memory userData) {
        TinfoilProof memory p = abi.decode(proof, (TinfoilProof));

        // 1. Reconstruct the signed envelope and recover the signer address
        bytes32 envelope = keccak256(abi.encodePacked(
            "tinfoil-release:",
            p.codeId, p.sigstoreDigest, p.dmVerityRoot,
            p.derivedCompressedPubkey, p.userData, bytes(p.domain)
        ));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", envelope));
        address recovered = _recoverSigner(ethHash, p.signerSig);

        // 2. Bind sig to claimed signer compressed pubkey
        if (recovered != _compressedPubkeyToAddress(p.signerCompressedPubkey)) revert InvalidTinfoilSignature();

        // 3. Look up signer as a bridge member and require canonical verifier codeId
        bytes32 signerMemberId = keccak256(p.signerCompressedPubkey);
        (bytes32 signerCodeId, , , , uint256 registeredAt) = bridge.getMember(signerMemberId);
        if (registeredAt == 0) revert VerifierNotRegistered();
        if (signerCodeId != verifierCodeId) revert VerifierWrongCode();

        return (p.codeId, p.derivedCompressedPubkey, p.userData);
    }

    function verifyAndCache(bytes calldata proof) external override returns (bytes32 codeId, bytes memory pubkey, bytes memory userData) {
        return this.verify(proof);
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig len");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }

    function _compressedPubkeyToAddress(bytes memory pk) internal view returns (address) {
        require(pk.length == 33, "need compressed pubkey");
        uint8 prefix = uint8(pk[0]);
        require(prefix == 0x02 || prefix == 0x03, "invalid prefix");

        uint256 x;
        assembly { x := mload(add(pk, 33)) }

        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 y2 = addmod(mulmod(mulmod(x, x, p), x, p), 7, p);
        uint256 y = _modExp(y2, (p + 1) / 4, p);
        if ((prefix == 0x02 && y % 2 != 0) || (prefix == 0x03 && y % 2 == 0)) y = p - y;

        return address(uint160(uint256(keccak256(abi.encodePacked(x, y)))));
    }

    function _modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exp, mod);
        bytes memory output = new bytes(32);
        assembly { if iszero(staticcall(gas(), 0x05, add(input, 32), 192, add(output, 32), 32)) { revert(0, 0) } }
        return abi.decode(output, (uint256));
    }
}
