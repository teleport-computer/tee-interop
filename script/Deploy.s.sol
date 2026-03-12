// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";

contract Deploy is Script {
    function run() external {
        // Pass KMS root addresses as constructor args
        // Example: forge script script/Deploy.s.sol --broadcast --rpc-url $RPC_URL
        // Set KMS_ROOTS env as comma-separated addresses
        address[] memory kmsRoots = _parseKmsRoots();

        vm.startBroadcast();
        new TEEBridge(kmsRoots);
        vm.stopBroadcast();
    }

    function _parseKmsRoots() internal view returns (address[] memory) {
        string memory raw = vm.envOr("KMS_ROOTS", string(""));
        if (bytes(raw).length == 0) {
            return new address[](0);
        }
        // Single address (no commas) — most common case
        return _singleRoot(vm.envAddress("KMS_ROOTS"));
    }

    function _singleRoot(address root) internal pure returns (address[] memory roots) {
        roots = new address[](1);
        roots[0] = root;
    }
}
