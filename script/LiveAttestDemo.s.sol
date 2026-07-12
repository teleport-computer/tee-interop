// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {AndroidKeyAttestationVerifier} from "../contracts/AndroidKeyAttestationVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";

/// @notice Registers a LIVE, physically-attached Pixel on-chain via an
/// explicitly-marked TESTNET verifier. The device is unlocked (orange), so a
/// production verifier would revert DeviceNotLocked. The testnet verifier still
/// runs the full path (genuine chain, StrongBox, challenge binding) and RECORDS
/// the true unlocked posture into the member's userData instead of rejecting.
/// Run with --ffi.
contract LiveAttestDemo is Script {
    bytes32 constant ROOT_FP =
        0xc1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5;

    // leaf challenge = SHA-256(nonce || apk_hash), as raw bytes (0x-hex to FFI)
    string constant CHALLENGE_HEX =
        "0x074b69d8c6ed0ac9ac29810ffe1102553d35f937e828950a7b6379bf0bb4e8a8";
    string constant LIVE_PEM =
        "/home/amiller/projects/dstack/edge-tee/pixel-attest/pixel_live_attestation.pem";

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        bytes32[] memory roots = new bytes32[](1);
        roots[0] = ROOT_FP;
        AndroidKeyAttestationVerifier verifier =
            new AndroidKeyAttestationVerifier(roots, true); // testnetMode = true

        TEEBridge bridge = new TEEBridge();
        bridge.addVerifier(address(verifier));

        bytes memory proof = _buildProof();

        (bytes32 codeId,,) = verifier.verify(proof);
        bridge.addAllowedCode(codeId);

        bytes32 memberId = bridge.register(address(verifier), proof);

        vm.stopBroadcast();

        console2.log("testnetMode: ", verifier.testnetMode());
        console2.log("verifier:    ", address(verifier));
        console2.log("bridge:      ", address(bridge));
        console2.log("memberId:");
        console2.logBytes32(memberId);
        console2.log("codeId (appCertSha256):");
        console2.logBytes32(codeId);
    }

    function _buildProof() internal returns (bytes memory) {
        string[] memory full = new string[](4);
        full[0] = "/home/amiller/projects/dstack/edge-tee/rt1180-se051/firmware/.venv/bin/python";
        full[1] = "tools/android_keyattest/build_proof.py";
        full[2] = LIVE_PEM;
        full[3] = CHALLENGE_HEX;
        return vm.ffi(full);
    }
}
