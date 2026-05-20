// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {AndroidKeyAttestationVerifier} from "../contracts/AndroidKeyAttestationVerifier.sol";

/// @dev Exercises AndroidKeyAttestationVerifier against a real Pixel 6 (oriole,
/// Android 16, Titan M2 StrongBox) cert chain captured 2026-05-20.
/// The proof is built off-chain via `tools/android_keyattest/build_proof.py`
/// invoked through `forge test --ffi`.
contract AndroidKeyAttestationVerifierTest is Test {
    AndroidKeyAttestationVerifier verifier;

    // SHA-256 of the root cert in test/fixtures/pixel6_strongbox.pem.
    bytes32 constant PIXEL6_ROOT_FP =
        0xc1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d5;

    // Challenge string that was bound into the captured leaf.
    string constant CAPTURED_CHALLENGE =
        "edge-tee-pixel6-first-attestation-20260520";

    string constant PEM_PATH = "test/fixtures/pixel6_strongbox.pem";

    function setUp() public {
        bytes32[] memory roots = new bytes32[](1);
        roots[0] = PIXEL6_ROOT_FP;
        verifier = new AndroidKeyAttestationVerifier(roots);
    }

    function _buildProof(string memory challenge) internal returns (bytes memory) {
        string[] memory inputs = new string[](3);
        inputs[0] = "tools/android_keyattest/build_proof.py";
        inputs[1] = PEM_PATH;
        inputs[2] = challenge;
        // Run via the project venv where eth_abi + cryptography are installed.
        string[] memory cmd = new string[](2);
        cmd[0] = "/home/amiller/projects/dstack/edge-tee/rt1180-se051/firmware/.venv/bin/python";
        // Re-pack as a single ffi call: python <args>
        string[] memory full = new string[](inputs.length + 1);
        full[0] = cmd[0];
        for (uint i = 0; i < inputs.length; i++) {
            full[i + 1] = inputs[i];
        }
        return vm.ffi(full);
    }

    function test_VerifyRealPixel6Proof() public {
        bytes memory proof = _buildProof(CAPTURED_CHALLENGE);
        (bytes32 codeId, bytes memory pubkey, bytes memory userData) =
            verifier.verify(proof);

        // codeId is the SHA-256 of the APK signing cert. For our debug-signed
        // edgetee-attest.apk, this is the SHA-256 of the auto-generated
        // androiddebugkey cert. We don't pin the exact value here (it depends
        // on the keystore that built the APK), only that it's non-zero.
        assertTrue(codeId != bytes32(0), "codeId must be non-zero");

        // Leaf pubkey is the SubjectPublicKeyInfo of the per-attestation key,
        // P-256. SPKI is ~91 bytes for a P-256 EC key.
        assertGt(pubkey.length, 50, "pubkey should be present");

        // userData is the challenge bound by the device.
        assertEq(userData, bytes(CAPTURED_CHALLENGE), "userData echoes the challenge");
    }

    function test_RootMustBeAllowlisted() public {
        bytes memory proof = _buildProof(CAPTURED_CHALLENGE);

        // Deploy a fresh verifier with NO roots.
        bytes32[] memory none = new bytes32[](0);
        AndroidKeyAttestationVerifier emptyVerifier =
            new AndroidKeyAttestationVerifier(none);

        vm.expectRevert(
            abi.encodeWithSelector(
                AndroidKeyAttestationVerifier.RootNotAllowed.selector,
                PIXEL6_ROOT_FP
            )
        );
        emptyVerifier.verify(proof);
    }

    function test_AppAllowlistEnforced() public {
        bytes memory proof = _buildProof(CAPTURED_CHALLENGE);
        // Extract the appCertSha256 by first verifying with the allowlist off,
        // then turn the allowlist on with the wrong hash and confirm it reverts.
        (bytes32 codeId, , ) = verifier.verify(proof);
        verifier.setRequireAppAllowlist(true);
        vm.expectRevert(
            abi.encodeWithSelector(
                AndroidKeyAttestationVerifier.AppCertNotAllowed.selector,
                codeId
            )
        );
        verifier.verify(proof);
        // Adding our app cert hash should make it pass again.
        verifier.addAllowedAppCert(codeId);
        verifier.verify(proof);
    }

    function test_MinOsPatchLevelEnforced() public {
        bytes memory proof = _buildProof(CAPTURED_CHALLENGE);
        // Pixel 6 patch from this capture was 2026-04-05 → osPatchLevel = 202604.
        verifier.setMinOsPatchLevel(202604);
        verifier.verify(proof);

        // Bump above the device's patch → should revert.
        verifier.setMinOsPatchLevel(202612);
        vm.expectRevert(
            abi.encodeWithSelector(
                AndroidKeyAttestationVerifier.OsPatchLevelTooLow.selector,
                202604,
                202612
            )
        );
        verifier.verify(proof);
    }
}
