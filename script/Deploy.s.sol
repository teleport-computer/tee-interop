// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script} from "forge-std/Script.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {DstackVerifier} from "../contracts/DstackVerifier.sol";
import {SigstoreAdapter} from "../contracts/SigstoreAdapter.sol";

contract Deploy is Script {
    function run() external {
        address[] memory kmsRoots = _parseKmsRoots();
        address sigstoreVerifier = vm.envOr("SIGSTORE_VERIFIER", address(0));

        vm.startBroadcast();

        DstackVerifier dstack = new DstackVerifier(kmsRoots);
        TEEBridge bridge = new TEEBridge();
        bridge.addVerifier(address(dstack));

        if (sigstoreVerifier != address(0)) {
            SigstoreAdapter sigAdapter = new SigstoreAdapter(sigstoreVerifier);
            bridge.addVerifier(address(sigAdapter));
        }

        vm.stopBroadcast();
    }

    function _parseKmsRoots() internal view returns (address[] memory) {
        string memory raw = vm.envOr("KMS_ROOTS", string(""));
        if (bytes(raw).length == 0) {
            return new address[](0);
        }
        return _singleRoot(vm.envAddress("KMS_ROOTS"));
    }

    function _singleRoot(address root) internal pure returns (address[] memory roots) {
        roots = new address[](1);
        roots[0] = root;
    }
}
