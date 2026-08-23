// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Script, console2} from "forge-std/Script.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {Stm32SecureManagerVerifier} from "../contracts/Stm32SecureManagerVerifier.sol";

/// @notice Deploys Stm32SecureManagerVerifier with the ST initial-attestation CA
///         key pre-pinned, and optionally wires it into an existing TEEBridge.
///
/// ST_CA_FP is SHA-256 over the X9.62 uncompressed encoding of the public key of
/// `CN=ST CA 01 for STM32 Initial Attestation`. ST delivers that certificate only
/// under licence, so the key is *determined* rather than published: intersecting
/// the candidate signers recovered from two independent leaves — a die we own and
/// the example certificate in UM3254 Rev 8 Figure 7 — leaves exactly one key.
/// Both halves are reproducible by anyone with the public user manual and any
/// STM32H573.
///
/// Unlike the SiLabs adapter this verifier checks the whole chain in-EVM (the
/// STM32 DUA chain is depth 2), so nothing trusts an off-chain chain walk.
///
/// The measurement (codeId) is the EAT -75006 `NSPE` hash: SHA-256 of the
/// operator's non-secure application as measured by SMuRoT. It is reproducible
/// offline from build output — see edge-tee stm32h5-stirot/host/nspe_measurement.py.
/// addAllowedCode is gated on env FW_MEASUREMENT.
///
///   forge script script/DeployStm32SecureManager.s.sol \
///     --rpc-url $BASE_SEPOLIA_RPC --broadcast
contract DeployStm32SecureManager is Script {
    /// SHA-256 of the X9.62 uncompressed ST init-attest CA public key
    /// 04e2a0eda5…bbcebae0 (determined 2026-08-23).
    bytes32 constant ST_CA_FP =
        0xac64f460233e6de4e2b4c5f5080ecaf503067d6aeef540ba76b51d081c12fdc9;

    function run() external {
        vm.startBroadcast();

        bytes32[] memory cas = new bytes32[](1);
        cas[0] = ST_CA_FP;
        Stm32SecureManagerVerifier verifier = new Stm32SecureManagerVerifier(cas);

        // Strict by default: only PSA lifecycle 0x3000 SECURED (PRODUCT_STATE
        // Closed) is accepted. Opt in to TZ-Closed parts with ACCEPT_DEV_MODE=true.
        if (vm.envOr("ACCEPT_DEV_MODE", false)) verifier.setAcceptDevMode(true);

        address existing = vm.envOr("TEEBRIDGE", address(0));
        if (existing != address(0)) {
            TEEBridge bridge = TEEBridge(existing);
            bridge.addVerifier(address(verifier));
            bytes32 fw = vm.envOr("FW_MEASUREMENT", bytes32(0));
            if (fw != bytes32(0)) bridge.addAllowedCode(fw);
            console2.log("wired into TEEBridge", existing);
        }

        console2.log("Stm32SecureManagerVerifier", address(verifier));
        console2.log("pinned ST CA fingerprint:");
        console2.logBytes32(ST_CA_FP);

        vm.stopBroadcast();
    }
}
