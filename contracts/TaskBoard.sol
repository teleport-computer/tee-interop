// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Minimal on-chain task board for attested edge nodes. A requester
/// posts a payload addressed to a bridge memberId; the node (a genuine attested
/// device) picks it up, signs the payload with its attestation-bound key, and
/// submits the signature. The contract verifies the ECDSA-P256 signature
/// ON-CHAIN via the RIP-7212 precompile at address(0x100) — proving a genuine
/// device holding the member's key executed the task, with no trust in the
/// off-chain caller.
///
/// The node key uses SHA256withECDSA (P-256). `assignee` is the bridge memberId
/// == keccak256(spki), where spki is the 91-byte DER SubjectPublicKeyInfo of the
/// node's P-256 key. On submit the caller supplies that same SPKI; the contract
/// re-derives the memberId from it (so the caller cannot substitute a key),
/// extracts (qx,qy) from its trailing 64 bytes (P-256 SPKI ends with
/// 0x04 || X[32] || Y[32]), and checks sha256(payload) against (r,s).
///
/// Off-chain the DER ECDSA-Sig-Value is parsed into (r,s) — that parse is not
/// security-sensitive (a wrong r/s simply fails the on-chain check).
contract TaskBoard {
    /// secp256r1 verification precompile (RIP-7212), native on Base.
    address constant P256_VERIFY = address(0x100);

    struct Task {
        bytes payload;
        bytes32 assignee;   // bridge memberId == keccak256(spki) expected to sign
        bool done;
        bytes signature;    // r||s (64 bytes) of the verified ECDSA-P256 signature
    }

    Task[] private tasks;

    event TaskPosted(uint256 indexed id, bytes32 indexed assignee, bytes payload);
    event TaskDone(uint256 indexed id, bytes signature);

    error AlreadyDone();
    error WrongAssignee(bytes32 got, bytes32 want);
    error BadSpki();
    error InvalidSignature();

    function post(bytes32 assignee, bytes calldata payload) external returns (uint256 id) {
        id = tasks.length;
        tasks.push(Task({payload: payload, assignee: assignee, done: false, signature: ""}));
        emit TaskPosted(id, assignee, payload);
    }

    /// @param id     Task index.
    /// @param spki   DER SubjectPublicKeyInfo of the node's P-256 key (91 bytes).
    ///               keccak256(spki) MUST equal the task's assignee.
    /// @param r,s    ECDSA-P256 signature over the raw payload (SHA256withECDSA),
    ///               DER-parsed off-chain into two 32-byte scalars.
    function submit(uint256 id, bytes calldata spki, bytes32 r, bytes32 s) external {
        Task storage t = tasks[id];
        if (t.done) revert AlreadyDone();

        bytes32 memberId = keccak256(spki);
        if (memberId != t.assignee) revert WrongAssignee(memberId, t.assignee);

        (bytes32 qx, bytes32 qy) = _pubkeyFromSpki(spki);
        bytes32 hash = sha256(t.payload);
        if (!_p256Verify(hash, r, s, qx, qy)) revert InvalidSignature();

        t.done = true;
        t.signature = abi.encodePacked(r, s);
        emit TaskDone(id, t.signature);
    }

    function get(uint256 id)
        external
        view
        returns (bytes memory payload, bytes32 assignee, bool done, bytes memory signature)
    {
        Task storage t = tasks[id];
        return (t.payload, t.assignee, t.done, t.signature);
    }

    function count() external view returns (uint256) {
        return tasks.length;
    }

    /// Extract (qx,qy) = the trailing 64 bytes of a P-256 SPKI (0x04||X||Y tail).
    function _pubkeyFromSpki(bytes calldata spki) internal pure returns (bytes32 qx, bytes32 qy) {
        uint256 n = spki.length;
        if (n < 65 || spki[n - 65] != 0x04) revert BadSpki();
        qx = bytes32(spki[n - 64:n - 32]);
        qy = bytes32(spki[n - 32:n]);
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
