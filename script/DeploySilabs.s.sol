// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {SilabsVerifier} from "../contracts/SilabsVerifier.sol";

/// @notice Deploys SilabsVerifier with the Silicon Labs Device Root CA pre-pinned
///         and wires it into a TEEBridge. Reuses an existing TEEBridge via env
///         TEEBRIDGE; otherwise deploys a fresh one.
///
/// SILABS_ROOT_FP is SHA-256 of the DER of Silicon Labs' published device-identity
/// root (CN=Device Root CA, O=Silicon Labs Inc., serial 12E6A2A59CAA27F9), the
/// anchor of SE-leaf -> Batch -> Factory -> Device Root CA. Full chain verified
/// offline 2026-06-11 against a live SiMG301 (BRD2719A).
///
/// The firmware measurement (codeId) is the EAT -75006 hash: the SE PRoT firmware
/// hash with secure boot off, or the secure-booted application (ARoT) hash once
/// provisioned. addAllowedCode is gated on env FW_MEASUREMENT.
contract DeploySilabs is Script {
    bytes32 constant SILABS_ROOT_FP =
        0xdbf5f0b3b3fded073c5f19289548e626adcb1f8f5346b93351c2d5775fa72153;

    function run() external {
        vm.startBroadcast();

        bytes32[] memory roots = new bytes32[](1);
        roots[0] = SILABS_ROOT_FP;
        SilabsVerifier verifier = new SilabsVerifier(roots);

        // Standalone, view-only deploy by default (like the Android verifier).
        // Opt into dev mode (no OTP burn) when ACCEPT_DEV_MODE=true.
        if (vm.envOr("ACCEPT_DEV_MODE", false)) verifier.setAcceptDevMode(true);

        // Optionally wire into an existing TEEBridge (set TEEBRIDGE); skip otherwise.
        address existing = vm.envOr("TEEBRIDGE", address(0));
        if (existing != address(0)) {
            TEEBridge bridge = TEEBridge(existing);
            bridge.addVerifier(address(verifier));
            bytes32 fw = vm.envOr("FW_MEASUREMENT", bytes32(0));
            if (fw != bytes32(0)) bridge.addAllowedCode(fw);
        }

        vm.stopBroadcast();
        console2.log("SilabsVerifier deployed at", address(verifier));
    }
}
