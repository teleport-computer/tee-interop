// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {SilabsVerifier} from "../contracts/SilabsVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

// Forge ships no 0x100 precompile, so we etch the canonical daimo/Ledger pure-
// Solidity RIP-7212 P-256 verifier at 0x100 — meaning this test performs a TRUE
// in-EVM secp256r1 verification of the LIVE device signature (no stub/mock). On
// Base, the native 0x100 precompile runs the identical check.

/// Live Silicon Labs Secure Vault attestation: SiMG301M104LIL (Series 3, PSA L4)
/// on BRD2719A, pulled 2026-06-11 via the se_manager_attestation firmware. The
/// PSA IAT (PSA_IOT_PROFILE_1, COSE_Sign1/ES256) is signed by the SE per-device
/// key whose cert chains EUI:20A716FFFEB31DAE -> Batch 1237800 -> Factory ->
/// Device Root CA (serial 12E6A2A5..., ca.silabs.com). Secure boot is OFF, so the
/// -75006 Software Components measurement is the SE PRoT firmware hash (one day an
/// ARoT app hash). Fields in test/fixtures/silabs/silabs_real_proof.json,
/// regenerable with tools/silabs/build_proof.py.
contract SilabsVerifierRealProofTest is Test {
    bytes constant PUBKEY =
        hex"0460af6eb5b0dc7a3b432bb45d1a18839e4a8546e2b322e3e0daede8289b30679cd01cb79c98686751ccdeb5125cf427e845879bc294422021620d40cc3e72ad8a";
    bytes32 constant DIGEST = 0x4a8c0f23c958ddee62bbc38c9966ee74917e85c4a16ff3881d4ec0cb7f460fb5;
    bytes32 constant R = 0x762e8755e155b2db46d38e97009be038af43a0981a3e0ef1bce8874bcc078492;
    bytes32 constant S = 0xe91be9c86e69b6c089bbe9b5e8fa4ed76d2115db3d909921db37d241603ee0e2;
    bytes32 constant MEASUREMENT = 0x830385b853d384f713df1bcbf1c5ec7daafce7d4fa783b7220410e3606c42fe6;
    bytes constant NONCE =
        hex"2e3e3885fa2bcb98f28fcd43927df604c288406d23304ea957649ebad35b9ea43ce3b5caf45a8103d98628a58cea3ef7d323818e8df305527e5730b188634dd1";
    // Secure boot is OFF on this part (no OTP burn) -> no ARoT -> dev mode.
    bool constant SECURE_BOOT = false;
    // SHA-256(DER) of the Silicon Labs Device Root CA (serial 12E6A2A59CAA27F9).
    bytes32 constant SILABS_ROOT_FP = 0xdbf5f0b3b3fded073c5f19289548e626adcb1f8f5346b93351c2d5775fa72153;

    SilabsVerifier verifier;
    TEEBridge bridge;

    function setUp() public {
        // Etch the real pure-Solidity P-256 verifier at the RIP-7212 address.
        vm.etch(address(0x100), address(new P256Verifier()).code);

        bytes32[] memory roots = new bytes32[](1);
        roots[0] = SILABS_ROOT_FP;
        verifier = new SilabsVerifier(roots);
        bridge = new TEEBridge();
    }

    function _realProof() internal pure returns (bytes memory) {
        return abi.encode(PUBKEY, DIGEST, R, S, MEASUREMENT, NONCE, SECURE_BOOT, SILABS_ROOT_FP);
    }

    // Dev-mode (no secure boot) is rejected by default — secure by default.
    function test_DevModeRejectedByDefault() public {
        assertFalse(verifier.acceptDevMode(), "default policy is strict");
        vm.expectRevert(SilabsVerifier.DevModeNotAccepted.selector);
        verifier.verify(_realProof());
    }

    // With acceptDevMode opted in, the live device's EAT verifies on-chain and
    // yields the right identity tuple (a TRUE in-EVM secp256r1 check of the sig).
    function test_LiveProofVerifies_WhenDevModeAccepted() public {
        verifier.setAcceptDevMode(true);
        (bytes32 codeId, bytes memory pubkey, bytes memory userData) = verifier.verify(_realProof());
        assertEq(codeId, MEASUREMENT, "codeId == live -75006 PRoT measurement");
        assertEq(pubkey, PUBKEY, "pubkey == live SE device key");
        assertEq(userData, abi.encode(NONCE, SECURE_BOOT), "userData == (nonce, secureBoot)");
    }

    // The live device registers as a TEEBridge member keyed by its device key.
    function test_LiveProofRegistersInBridge() public {
        verifier.setAcceptDevMode(true);
        bridge.addVerifier(address(verifier));
        bridge.addAllowedCode(MEASUREMENT);
        bytes32 memberId = bridge.register(address(verifier), _realProof());
        assertEq(memberId, keccak256(PUBKEY), "member keyed by keccak256(device key)");
        assertTrue(bridge.isMember(memberId), "live device is a registered member");
        (bytes32 codeId,,,,) = bridge.getMember(memberId);
        assertEq(codeId, MEASUREMENT, "stored codeId == live measurement");
    }

    // Wrong root fingerprint (not the SiLabs Device Root CA) is rejected.
    function test_LiveProofWrongRootReverts() public {
        bytes memory bad = abi.encode(PUBKEY, DIGEST, R, S, MEASUREMENT, NONCE, SECURE_BOOT, bytes32(uint256(0xBAD)));
        vm.expectRevert();
        verifier.verify(bad);
    }

    // A tampered signature fails the in-EVM P-256 check.
    function test_TamperedSigReverts() public {
        verifier.setAcceptDevMode(true);
        bytes32 badS = bytes32(uint256(S) ^ 1);
        bytes memory bad = abi.encode(PUBKEY, DIGEST, R, badS, MEASUREMENT, NONCE, SECURE_BOOT, SILABS_ROOT_FP);
        vm.expectRevert(SilabsVerifier.InvalidSignature.selector);
        verifier.verify(bad);
    }
}
