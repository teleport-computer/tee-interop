// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {SilabsVerifier} from "../contracts/SilabsVerifier.sol";
import {DstackVerifier} from "../contracts/DstackVerifier.sol";

/// Stand up the heterogeneous-interop registry on Base Sepolia:
///   - fresh TEEBridge
///   - DstackVerifier (KMS roots added later, once tee-daemon's proof is fetched)
///   - wire in the already-deployed SilabsVerifier (env SILABS_VERIFIER)
///   - register the live SiMG301 edge-MCU attestation as member 1
/// tee-daemon's Phala TDX CVM registers as member 2 in a later step.
contract DeployInteropSepolia is Script {
    function run() external {
        address silabs = vm.envAddress("SILABS_VERIFIER");
        string memory j = vm.readFile("test/fixtures/silabs/silabs_real_proof.json");
        bytes32 meas = vm.parseJsonBytes32(j, ".measurement");

        // NB: register(silabs, proof) is done via `cast send` against the live node,
        // not here — forge's local EVM lacks Base's native P256 precompile at 0x100.
        vm.startBroadcast();
        TEEBridge bridge = new TEEBridge();
        DstackVerifier dstack = new DstackVerifier(new address[](0));

        bridge.addVerifier(silabs);
        bridge.addVerifier(address(dstack));
        bridge.addAllowedCode(meas);              // admit the SiLabs PRoT measurement
        vm.stopBroadcast();

        console2.log("TEEBridge       ", address(bridge));
        console2.log("DstackVerifier  ", address(dstack));
        console2.log("SilabsVerifier  ", silabs);
        console2.log("OK: bridge wired; now register SiLabs via cast send");
    }
}
