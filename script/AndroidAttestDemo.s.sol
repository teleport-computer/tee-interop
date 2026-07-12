// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {AndroidKeyAttestationVerifier} from "../contracts/AndroidKeyAttestationVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";

/// @notice End-to-end Android Key Attestation demo: deploys P256Verifier +
/// AndroidKeyAttestationVerifier + TEEBridge, builds a proof from the captured
/// Pixel 6 chain via FFI, and registers the device as a TEEBridge member.
/// Run with --ffi.
contract AndroidAttestDemo is Script {
    bytes32 constant ROOT_FP =
        0xc1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5;

    string constant CHALLENGE = "edge-tee-pixel6-agree-key-20260524";

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        bytes32[] memory roots = new bytes32[](1);
        roots[0] = ROOT_FP;
        AndroidKeyAttestationVerifier verifier =
            new AndroidKeyAttestationVerifier(roots, false);

        TEEBridge bridge = new TEEBridge();
        bridge.addVerifier(address(verifier));

        bytes memory proof = _buildProof();

        (bytes32 codeId,,) = verifier.verify(proof);
        bridge.addAllowedCode(codeId);

        bytes32 memberId = bridge.register(address(verifier), proof);

        vm.stopBroadcast();

        console2.log("verifier:    ", address(verifier));
        console2.log("bridge:      ", address(bridge));
        console2.log("memberId:");
        console2.logBytes32(memberId);
        console2.log("codeId:");
        console2.logBytes32(codeId);
    }

    function _buildProof() internal returns (bytes memory) {
        string[] memory full = new string[](4);
        full[0] = "/home/amiller/projects/dstack/edge-tee/rt1180-se051/firmware/.venv/bin/python";
        full[1] = "tools/android_keyattest/build_proof.py";
        full[2] = "test/fixtures/pixel6_strongbox.pem";
        full[3] = CHALLENGE;
        return vm.ffi(full);
    }
}
