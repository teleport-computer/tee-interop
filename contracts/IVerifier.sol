// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IVerifier {
    /// @notice Pure verification — no state changes. Use for off-chain checks or view-compatible verifiers.
    function verify(bytes calldata proof) external view returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);

    /// @notice Verification with optional caching (e.g. Nitro cert chain). Defaults to calling verify().
    function verifyAndCache(bytes calldata proof) external returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);
}
