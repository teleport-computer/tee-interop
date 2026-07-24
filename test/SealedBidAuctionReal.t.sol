// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {SealedBidAuction} from "../contracts/SealedBidAuction.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

/// Etches the pure-Solidity RIP-7212 verifier at 0x100 so resolve() performs a
/// TRUE in-EVM secp256r1 check of the loader's transcript signature (no stub).
/// The loader signs sha256(workloadId || input || output) with SHA256withECDSA
/// under the announced P-256 key.
contract SealedBidAuctionRealTest is Test {
    bytes constant ANNOUNCE_KEY =
        hex"3059301306072a8648ce3d020106082a8648ce3d03010703420004471c3e758c4904285bba7e53118ed0f524adeb0757d25bd2f8e7b0d76dfa714cdd520f7aca8a8b917acc37f51de8f0c9bbe3ad858382e702dc25a12d09f7a858";
    bytes32 constant WORKLOAD_ID = 0x8569c83567e1c19a0c25b965fb3ef282c110510cd31821eca3472290641c3604;
    bytes constant INPUT = '[{"c":"0xabc"},{"c":"0xdef"},{"c":"0x111"}]';
    bytes constant OUTPUT = '{"winner":1,"price":42}';
    bytes32 constant R = 0xcadcd4789a82f37fb8cd0020e3a872f187f174e1f4499b04557d5132e3ea08b7;
    bytes32 constant S = 0x32125800f44b0e5655f0d3efdee08d6a7d73b0abac4e84b8a0887162666627b8;

    SealedBidAuction auction;

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        auction = new SealedBidAuction();
    }

    function _seed() internal returns (uint256 id) {
        id = auction.create(WORKLOAD_ID, ANNOUNCE_KEY);
        auction.bid(id, "0xabc");
        auction.bid(id, "0xdef");
        auction.bid(id, "0x111");
    }

    // A valid transcript signature verifies on-chain; output is stored as truth.
    function test_ValidResolveSucceeds() public {
        uint256 id = _seed();
        auction.resolve(id, 1, 42, INPUT, OUTPUT, R, S);
        (, , , bool resolved, uint256 winner, uint256 price) = auction.get(id);
        assertTrue(resolved, "resolved");
        assertEq(winner, 1);
        assertEq(price, 42);
        assertEq(auction.getRecord(id), OUTPUT, "output bound as source of truth");
    }

    // A tampered signature fails the in-EVM P-256 check.
    function test_TamperedSignatureReverts() public {
        uint256 id = _seed();
        bytes32 badS = bytes32(uint256(S) ^ 1);
        vm.expectRevert(SealedBidAuction.InvalidSignature.selector);
        auction.resolve(id, 1, 42, INPUT, OUTPUT, R, badS);
    }

    // A tampered output changes the digest; the good sig no longer verifies.
    function test_TamperedOutputReverts() public {
        uint256 id = _seed();
        vm.expectRevert(SealedBidAuction.InvalidSignature.selector);
        auction.resolve(id, 1, 42, INPUT, '{"winner":0,"price":99}', R, S);
    }

    // A tampered input (different consumed ciphertext bundle) reverts.
    function test_TamperedInputReverts() public {
        uint256 id = _seed();
        vm.expectRevert(SealedBidAuction.InvalidSignature.selector);
        auction.resolve(id, 1, 42, "different-input", OUTPUT, R, S);
    }
}
