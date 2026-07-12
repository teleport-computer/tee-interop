// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Minimal on-chain task board for attested edge nodes. A requester
/// posts a payload addressed to a bridge memberId; the node (a genuine attested
/// device) picks it up, signs the payload with its attestation-bound key, and
/// submits the signature. Anyone verifies the signature off-chain against the
/// member's registered pubkey — proving a genuine device executed the task.
/// (Signature verification is off-chain: on-chain P-256 is out of scope here,
/// same as the AndroidKeyAttestationVerifier chain check.)
contract TaskBoard {
    struct Task {
        bytes payload;
        bytes32 assignee;   // bridge memberId expected to sign
        bool done;
        bytes signature;    // DER ECDSA-P256 over payload, by the node key
    }

    Task[] private tasks;

    event TaskPosted(uint256 indexed id, bytes32 indexed assignee, bytes payload);
    event TaskDone(uint256 indexed id, bytes signature);

    function post(bytes32 assignee, bytes calldata payload) external returns (uint256 id) {
        id = tasks.length;
        tasks.push(Task({payload: payload, assignee: assignee, done: false, signature: ""}));
        emit TaskPosted(id, assignee, payload);
    }

    function submit(uint256 id, bytes calldata signature) external {
        Task storage t = tasks[id];
        require(!t.done, "already done");
        t.done = true;
        t.signature = signature;
        emit TaskDone(id, signature);
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
}
