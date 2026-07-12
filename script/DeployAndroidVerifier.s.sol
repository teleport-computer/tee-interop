// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {AndroidKeyAttestationVerifier} from "../contracts/AndroidKeyAttestationVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";

/// @notice Deploy-only script (no register call). Each deploy fits under
/// the Base sequencer's per-tx gas cap (~17M); the register call (52M
/// chain verification) doesn't, so it must be invoked via a higher-limit
/// path (e.g. a node with a custom tx gas limit override) or split.
contract DeployAndroidVerifier is Script {
    // Stock Pixel chain's bundled "Key Attestation CA1" root.
    bytes32 constant ROOT_FP =
        0xc1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5;
    // Google root the GrapheneOS appliance chain terminates at
    // (also in tools/android_keyattest/roots.json).
    bytes32 constant APPLIANCE_ROOT_FP =
        0x6d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0;
    // vbmeta digest of our Pixel 6a appliance image: GrapheneOS 2026052400 +
    // com.edgetee.attest baked into /system/priv-app. Titan M2 measures it.
    bytes32 constant APPLIANCE_BOOT_HASH =
        0xa6f60a727d5df935040c54cdd57cd0f57d5cec6eac277586d96b3a8701295a74;

    function run() external {
        uint256 pk = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(pk);

        bytes32[] memory roots = new bytes32[](2);
        roots[0] = ROOT_FP;
        roots[1] = APPLIANCE_ROOT_FP;
        AndroidKeyAttestationVerifier verifier =
            new AndroidKeyAttestationVerifier(roots, false);
        verifier.addAllowedBootHash(APPLIANCE_BOOT_HASH);

        TEEBridge bridge = new TEEBridge();
        bridge.addVerifier(address(verifier));

        vm.stopBroadcast();

        console2.log("verifier:    ", address(verifier));
        console2.log("bridge:      ", address(bridge));
        console2.log("appliance boot hash allow-listed:");
        console2.logBytes32(APPLIANCE_BOOT_HASH);
    }
}
