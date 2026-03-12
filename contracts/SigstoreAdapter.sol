// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IVerifier} from "./IVerifier.sol";
import {ISigstoreVerifier} from "./ISigstoreVerifier.sol";

contract SigstoreAdapter is IVerifier {
    ISigstoreVerifier public immutable sigstore;

    constructor(address _sigstore) {
        sigstore = ISigstoreVerifier(_sigstore);
    }

    function verify(bytes calldata proof) external view override returns (bytes32 codeId, bytes memory pubkey) {
        (bytes memory zkProof, bytes32[] memory publicInputs, bytes memory compressedPubkey, bytes memory ownershipSig)
            = abi.decode(proof, (bytes, bytes32[], bytes, bytes));

        ISigstoreVerifier.Attestation memory att = sigstore.verifyAndDecode(zkProof, publicInputs);

        // Ownership: signer of keccak256(zkProof) must match compressedPubkey
        bytes32 msgHash = keccak256(zkProof);
        address signer = _recoverSigner(msgHash, ownershipSig);
        require(signer == _compressedPubkeyToAddress(compressedPubkey), "ownership mismatch");

        return (bytes32(att.commitSha), compressedPubkey);
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

    function _compressedPubkeyToAddress(bytes memory pubkey) internal view returns (address) {
        require(pubkey.length == 33, "need compressed pubkey");
        uint8 prefix = uint8(pubkey[0]);
        require(prefix == 0x02 || prefix == 0x03, "invalid prefix");

        uint256 x;
        assembly { x := mload(add(pubkey, 33)) }

        uint256 p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
        uint256 y2 = addmod(mulmod(mulmod(x, x, p), x, p), 7, p);
        uint256 y = _modExp(y2, (p + 1) / 4, p);

        if ((prefix == 0x02 && y % 2 != 0) || (prefix == 0x03 && y % 2 == 0)) {
            y = p - y;
        }

        bytes32 hash = keccak256(abi.encodePacked(x, y));
        return address(uint160(uint256(hash)));
    }

    function _modExp(uint256 base, uint256 exp, uint256 mod) internal view returns (uint256) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), base, exp, mod);
        bytes memory output = new bytes(32);
        assembly {
            if iszero(staticcall(gas(), 0x05, add(input, 32), 192, add(output, 32), 32)) { revert(0, 0) }
        }
        return abi.decode(output, (uint256));
    }
}
