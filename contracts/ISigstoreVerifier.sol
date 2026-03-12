// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title ISigstoreVerifier
/// @notice Interface for verifying Sigstore attestations via ZK proofs
interface ISigstoreVerifier {
    struct Attestation {
        bytes32 artifactHash;
        bytes32 repoHash;
        bytes20 commitSha;
    }

    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external view returns (bool valid);

    function verifyAndDecode(bytes calldata proof, bytes32[] calldata publicInputs)
        external view returns (Attestation memory attestation);

    function decodePublicInputs(bytes32[] calldata publicInputs)
        external pure returns (Attestation memory attestation);
}
