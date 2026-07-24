// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/// @notice Sealed-bid second-price auctions resolved by an attested edge
/// coprocessor. The auction LOGIC is a JavaScript payload measured as
/// workloadId = sha256(js), run in a measured WASM loader on an attested
/// device. Bids are posted ECIES-encrypted to the workload's hardware key
/// (announced here as announceKey, a DER P-256 SPKI).
///
/// The measured loader signs a transcript
///   transcript = workloadId || input || output          (raw bytes concatenated)
/// with SHA256withECDSA under the workload's attested P-256 key. `input` is the
/// bid ciphertext bundle the loader consumed, `output` is the revealed result.
/// `resolve` re-checks that signature ON-CHAIN via the RIP-7212 precompile at
/// address(0x100) against the stored announceKey — so the winner/price the
/// caller announces are backed by a signature the device produced, not trusted.
///
/// `output` is the cryptographically-bound source of truth. `winner`/`price`
/// are caller-provided convenience fields (a decode of `output`) and carry no
/// independent authority — consumers should read `output`.
contract SealedBidAuction {
    /// secp256r1 verification precompile (RIP-7212), native on Base.
    address constant P256_VERIFY = address(0x100);

    struct Auction {
        bytes32 workloadId;    // sha256 of the auction JS
        bytes announceKey;     // DER SPKI of the workload's attested P-256 key
        bytes[] bids;          // ECIES bundles (JSON), one per bidder
        bool resolved;
        uint256 winner;        // winning bid index (convenience decode of output)
        uint256 price;         // clearing price (convenience decode of output)
        bytes output;          // the signed, cryptographically-bound result bytes
    }

    Auction[] private auctions;

    event AuctionCreated(uint256 indexed id, bytes32 workloadId, bytes announceKey);
    event BidPlaced(uint256 indexed id, uint256 indexed bidIndex, bytes ciphertext);
    event Resolved(uint256 indexed id, uint256 winner, uint256 price, bytes output);

    error Resolved_();
    error BadWinner();
    error BadSpki();
    error InvalidSignature();

    function create(bytes32 workloadId, bytes calldata announceKey) external returns (uint256 id) {
        id = auctions.length;
        Auction storage a = auctions.push();
        a.workloadId = workloadId;
        a.announceKey = announceKey;
        emit AuctionCreated(id, workloadId, announceKey);
    }

    function bid(uint256 id, bytes calldata ciphertext) external returns (uint256 bidIndex) {
        Auction storage a = auctions[id];
        if (a.resolved) revert Resolved_();
        bidIndex = a.bids.length;
        a.bids.push(ciphertext);
        emit BidPlaced(id, bidIndex, ciphertext);
    }

    /// @param id      Auction index.
    /// @param winner  Winning bid index (convenience; must decode from output off-chain).
    /// @param price   Clearing price (convenience).
    /// @param input   The exact bid-ciphertext bundle the loader consumed.
    /// @param output  The revealed result bytes the loader signed (source of truth).
    /// @param r,s     ECDSA-P256 signature over sha256(workloadId || input || output),
    ///                under the announced key (SHA256withECDSA), DER-parsed off-chain.
    function resolve(
        uint256 id,
        uint256 winner,
        uint256 price,
        bytes calldata input,
        bytes calldata output,
        bytes32 r,
        bytes32 s
    ) external {
        Auction storage a = auctions[id];
        if (a.resolved) revert Resolved_();
        if (winner >= a.bids.length) revert BadWinner();

        (bytes32 qx, bytes32 qy) = _pubkeyFromSpki(a.announceKey);
        bytes32 hash = sha256(abi.encodePacked(a.workloadId, input, output));
        if (!_p256Verify(hash, r, s, qx, qy)) revert InvalidSignature();

        a.resolved = true;
        a.winner = winner;
        a.price = price;
        a.output = output;
        emit Resolved(id, winner, price, output);
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

    /// The signed result bytes bound by the transcript signature (source of truth).
    function getRecord(uint256 id) external view returns (bytes memory) {
        return auctions[id].output;
    }

    function count() external view returns (uint256) {
        return auctions.length;
    }

    /// Extract (qx,qy) = the trailing 64 bytes of a P-256 SPKI (0x04||X||Y tail).
    function _pubkeyFromSpki(bytes memory spki) internal pure returns (bytes32 qx, bytes32 qy) {
        uint256 n = spki.length;
        if (n < 65 || spki[n - 65] != 0x04) revert BadSpki();
        assembly {
            qx := mload(add(spki, add(0x20, sub(n, 64))))
            qy := mload(add(spki, add(0x20, sub(n, 32))))
        }
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
