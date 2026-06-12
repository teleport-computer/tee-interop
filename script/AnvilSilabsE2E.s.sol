// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {SilabsVerifier} from "../contracts/SilabsVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";

/// End-to-end on a live chain (anvil): deploy SilabsVerifier + TEEBridge, opt into
/// dev mode, then verify + register the LIVE SiMG301 attestation proof from the
/// fixture. Assumes the RIP-7212 P256 precompile is present at 0x100 (native on
/// Base; install on anvil via `cast rpc anvil_setCode 0x...0100 <P256 code>`).
/// Reads test/fixtures/silabs/silabs_real_proof.json.
contract AnvilSilabsE2E is Script {
    function run() external {
        string memory j = vm.readFile("test/fixtures/silabs/silabs_real_proof.json");
        bytes memory proof = vm.parseJsonBytes(j, ".proof");
        bytes32 meas = vm.parseJsonBytes32(j, ".measurement");
        bytes32 rootFp = vm.parseJsonBytes32(j, ".silabsRootFingerprint");
        bytes memory pubkey = vm.parseJsonBytes(j, ".devicePubkeyXY");

        vm.startBroadcast();
        bytes32[] memory roots = new bytes32[](1);
        roots[0] = rootFp;
        SilabsVerifier verifier = new SilabsVerifier(roots);
        TEEBridge bridge = new TEEBridge();

        verifier.setAcceptDevMode(true);          // accept un-provisioned (no OTP burn)
        bridge.addVerifier(address(verifier));
        bridge.addAllowedCode(meas);              // allow the PRoT dev-mode measurement

        bridge.register(address(verifier), proof); // verifies in-EVM via 0x100
        vm.stopBroadcast();

        bytes32 memberId = keccak256(pubkey);
        require(bridge.isMember(memberId), "device not registered");
        (bytes32 stored,,,,) = bridge.getMember(memberId);
        require(stored == meas, "codeId mismatch");

        console2.log("verifier   ", address(verifier));
        console2.log("bridge     ", address(bridge));
        console2.log("memberId   ", vm.toString(memberId));
        console2.log("codeId     ", vm.toString(stored));
        console2.log("PASS: live SiMG301 attestation verified + registered on anvil");
    }
}
