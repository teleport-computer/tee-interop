// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Sealed-bid second-price auctions resolved by an attested edge
/// coprocessor. The auction LOGIC is a JavaScript payload measured as
/// workloadId = sha256(js), run in a measured WASM loader on an attested
/// device. Bids are posted ECIES-encrypted to the workload's hardware key
/// (announced here); the resolution reveals ONLY the winner index and the
/// clearing (second) price, plus a signed transcript binding
/// (workloadId, the ciphertexts, the result) — verifiable off-chain against
/// the device's key-attestation chain.
contract SealedBidAuction {
    struct Auction {
        bytes32 workloadId;    // sha256 of the auction JS
        bytes announceKey;     // SPKI of the workload's attested P-256 key
        bytes[] bids;          // ECIES bundles (JSON), one per bidder
        bool resolved;
        uint256 winner;        // winning bid index
        uint256 price;         // clearing price (second-highest bid)
        bytes record;          // loader transcript record + cert chain (JSON)
    }

    Auction[] private auctions;

    event AuctionCreated(uint256 indexed id, bytes32 workloadId, bytes announceKey);
    event BidPlaced(uint256 indexed id, uint256 indexed bidIndex, bytes ciphertext);
    event Resolved(uint256 indexed id, uint256 winner, uint256 price);

    function create(bytes32 workloadId, bytes calldata announceKey) external returns (uint256 id) {
        id = auctions.length;
        Auction storage a = auctions.push();
        a.workloadId = workloadId;
        a.announceKey = announceKey;
        emit AuctionCreated(id, workloadId, announceKey);
    }

    function bid(uint256 id, bytes calldata ciphertext) external returns (uint256 bidIndex) {
        Auction storage a = auctions[id];
        require(!a.resolved, "resolved");
        bidIndex = a.bids.length;
        a.bids.push(ciphertext);
        emit BidPlaced(id, bidIndex, ciphertext);
    }

    function resolve(uint256 id, uint256 winner, uint256 price, bytes calldata record) external {
        Auction storage a = auctions[id];
        require(!a.resolved, "resolved");
        require(winner < a.bids.length, "bad winner");
        a.resolved = true;
        a.winner = winner;
        a.price = price;
        a.record = record;
        emit Resolved(id, winner, price);
    }

    function get(uint256 id) external view returns (
            bytes32 workloadId, bytes memory announceKey, uint256 nBids,
            bool resolved, uint256 winner, uint256 price) {
        Auction storage a = auctions[id];
        return (a.workloadId, a.announceKey, a.bids.length, a.resolved, a.winner, a.price);
    }

    function getBid(uint256 id, uint256 i) external view returns (bytes memory) {
        return auctions[id].bids[i];
    }

    function getRecord(uint256 id) external view returns (bytes memory) {
        return auctions[id].record;
    }

    function count() external view returns (uint256) {
        return auctions.length;
    }
}
