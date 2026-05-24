// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {PixelFaucet} from "../contracts/PixelFaucet.sol";

contract DeployPixelFaucet is Script {
    function run() external {
        address relayer = vm.envAddress("RELAYER");
        address verifier = vm.envAddress("VERIFIER");

        vm.startBroadcast();
        PixelFaucet faucet = new PixelFaucet(relayer, verifier);
        vm.stopBroadcast();

        console2.log("PixelFaucet:", address(faucet));
        console2.log("  relayer:", relayer);
        console2.log("  verifier:", verifier);
    }
}
