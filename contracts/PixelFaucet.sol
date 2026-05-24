// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @title PixelFaucet
/// @notice Lets any attested Pixel "tag" the contract once per device.
///
/// On-chain verification of an Android Key Attestation chain (~50M gas)
/// exceeds Base Sepolia's 16.7M per-tx cap, so the actual chain check is
/// done off-chain by a relayer — which view-calls the deployed
/// AndroidKeyAttestationVerifier, confirms the chain is valid + the
/// challenge encodes `(chainId, contract, to, message)`, then signs a
/// permit. This contract verifies the relayer signature and emits a
/// Tagged event.
///
/// Auditability: the relayer publishes the .pem next to a `Tagged` event;
/// the event's `pemHash` lets anyone re-do the view call against the
/// AndroidKeyAttestationVerifier and confirm the relayer signed honestly.
///
/// `deviceFingerprint` for the demo is `keccak256(certs[1])` — the
/// per-device StrongBox attestation-key cert hash. Stable across leaf
/// rotations (a new leaf per attestation call), but rotates whenever
/// Android RKP refreshes the StrongBox key (typically every few weeks).
contract PixelFaucet {
    address public owner;
    address public relayer;
    address public immutable verifier;
    uint256 public taggedCount;

    /// One claim per device fingerprint.
    mapping(bytes32 => bool) public claimed;
    /// to-address → device fingerprint that claimed there (for reverse lookup).
    mapping(address => bytes32) public firstClaimByAddr;

    event Tagged(
        bytes32 indexed deviceFingerprint,
        address indexed to,
        string message,
        bytes32 pemHash,
        bytes32 codeId,
        uint256 timestamp
    );
    event RelayerSet(address indexed relayer);
    event OwnerSet(address indexed owner);

    error NotOwner();
    error AlreadyClaimed();
    error Expired();
    error BadRelayerSig();
    error MessageTooLong();
    error ZeroFingerprint();

    constructor(address _relayer, address _verifier) {
        owner = msg.sender;
        relayer = _relayer;
        verifier = _verifier;
        emit OwnerSet(msg.sender);
        emit RelayerSet(_relayer);
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    function setRelayer(address _relayer) external onlyOwner {
        relayer = _relayer;
        emit RelayerSet(_relayer);
    }

    function setOwner(address _owner) external onlyOwner {
        owner = _owner;
        emit OwnerSet(_owner);
    }

    /// @notice Submit a relayer-signed claim permit and tag the wall.
    /// @param deviceFingerprint keccak256 of the per-device StrongBox cert
    /// @param to recipient address bound into the attestation challenge
    /// @param message short tag message (max 140 bytes)
    /// @param pemHash keccak256 of the full chain PEM the relayer used
    /// @param codeId keccak256 of the leaf cert DER (from verifier.verify)
    /// @param deadline unix timestamp after which this permit is rejected
    /// @param relayerSig EIP-191 signature by `relayer` over the permit digest
    function claim(
        bytes32 deviceFingerprint,
        address to,
        string calldata message,
        bytes32 pemHash,
        bytes32 codeId,
        uint256 deadline,
        bytes calldata relayerSig
    ) external {
        if (block.timestamp > deadline) revert Expired();
        if (deviceFingerprint == bytes32(0)) revert ZeroFingerprint();
        if (claimed[deviceFingerprint]) revert AlreadyClaimed();
        if (bytes(message).length > 140) revert MessageTooLong();

        bytes32 digest = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                "pixel-faucet/v1",
                deviceFingerprint,
                to,
                keccak256(bytes(message)),
                pemHash,
                codeId,
                deadline
            )
        );
        bytes32 ethDigest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        address signer = _recover(ethDigest, relayerSig);
        if (signer != relayer) revert BadRelayerSig();

        claimed[deviceFingerprint] = true;
        if (firstClaimByAddr[to] == bytes32(0)) {
            firstClaimByAddr[to] = deviceFingerprint;
        }
        unchecked { taggedCount++; }

        emit Tagged(deviceFingerprint, to, message, pemHash, codeId, block.timestamp);
    }

    /// @dev Single-shot ecrecover with malleability check (s in lower half).
    function _recover(bytes32 hash, bytes calldata sig) private pure returns (address) {
        if (sig.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        if (v != 27 && v != 28) return address(0);
        return ecrecover(hash, v, r, s);
    }
}
