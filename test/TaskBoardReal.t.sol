// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {TaskBoard} from "../contracts/TaskBoard.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

/// Forge ships no 0x100 precompile, so we etch the pure-Solidity RIP-7212
/// verifier at 0x100 — meaning submit() performs a TRUE in-EVM secp256r1 check
/// of the node signature (no stub). On Base the native 0x100 precompile is used.
///
/// Vectors from a fixed P-256 key (see test/../scripts). The node signs the raw
/// payload with SHA256withECDSA; assignee = keccak256(spki).
contract TaskBoardRealTest is Test {
    // 91-byte DER SubjectPublicKeyInfo of the node's P-256 key.
    bytes constant SPKI =
        hex"3059301306072a8648ce3d020106082a8648ce3d03010703420004471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714cdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858";
    bytes constant PAYLOAD = "resize image task #7: rotate 90 and thumbnail";
    bytes32 constant R = 0x15e2327cdf094d3ce13ff7522c28467c5a7578f45b959b2c1a583bda66e1cb94;
    bytes32 constant S = 0x1618649d2400b7a644c0d2dfeb3f9bc4cb1bc5c8f1ae7c6856de93eb4c9b6f94;

    TaskBoard board;

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        board = new TaskBoard();
    }

    function _memberId() internal pure returns (bytes32) {
        return keccak256(SPKI);
    }

    // A valid signature over the real payload verifies on-chain and marks done.
    function test_ValidSignatureSucceeds() public {
        uint256 id = board.post(_memberId(), PAYLOAD);
        board.submit(id, SPKI, R, S);
        (, , bool done, bytes memory sig) = board.get(id);
        assertTrue(done, "task marked done");
        assertEq(sig, abi.encodePacked(R, S), "stored r||s");
    }

    // A tampered signature (flipped s) fails the in-EVM P-256 check.
    function test_TamperedSignatureReverts() public {
        uint256 id = board.post(_memberId(), PAYLOAD);
        bytes32 badS = bytes32(uint256(S) ^ 1);
        vm.expectRevert(TaskBoard.InvalidSignature.selector);
        board.submit(id, SPKI, R, badS);
    }

    // A tampered payload changes sha256(payload); the good sig no longer verifies.
    function test_TamperedPayloadReverts() public {
        uint256 id = board.post(_memberId(), "resize image task #7: rotate 91 and thumbnail");
        vm.expectRevert(TaskBoard.InvalidSignature.selector);
        board.submit(id, SPKI, R, S);
    }

    // Supplying a key that doesn't match the assignee memberId reverts before verify.
    function test_WrongAssigneeReverts() public {
        uint256 id = board.post(keccak256("someone else"), PAYLOAD);
        vm.expectRevert(
            abi.encodeWithSelector(TaskBoard.WrongAssignee.selector, _memberId(), keccak256("someone else"))
        );
        board.submit(id, SPKI, R, S);
    }
}
