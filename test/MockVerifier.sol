// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// Mock IVerifier-shaped contract for anvil dry-runs of the PixelFaucet flow.
/// Accepts any proof shape `(bytes[] certs, bytes challenge)` and returns
/// (codeId = keccak256(certs[0]), pubkey = certs[0], userData = challenge).
/// Real chain verification is exercised against the deployed AndroidKey-
/// AttestationVerifier at 0x82e5... on Base Sepolia.
contract MockVerifier {
    struct AndroidProof {
        bytes[] certs;
        bytes challenge;
    }

    function verify(bytes calldata proof)
        external
        pure
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData)
    {
        AndroidProof memory p = abi.decode(proof, (AndroidProof));
        require(p.certs.length >= 2, "chain too short");
        codeId = keccak256(p.certs[0]);
        pubkey = p.certs[0];
        userData = p.challenge;
    }
}
