// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IVerifier {
    function verify(bytes calldata proof) external view returns (bytes32 codeId, bytes memory pubkey);
}
