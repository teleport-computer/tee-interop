// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {Test} from "forge-std/Test.sol";
import {Stm32SecureManagerVerifier} from "../contracts/Stm32SecureManagerVerifier.sol";
import {TEEBridge} from "../contracts/TEEBridge.sol";
import {P256Verifier} from "./vendor/P256Verifier.sol";

// Forge ships no 0x100 precompile, so we etch the canonical daimo/Ledger pure-
// Solidity RIP-7212 P-256 verifier at 0x100 — meaning these tests perform TRUE
// in-EVM secp256r1 verifications of the LIVE device signatures (no stub/mock).
// On Base, the native 0x100 precompile runs the identical check.

/// Live STM32H573 Secure Manager attestation, pulled 2026-08-23 from the
/// STM32H573I-DK after provisioning Secure Manager 2.1.0 / SMuRoT 2.0.0 and
/// progressing PRODUCT_STATE to Closed (PSA lifecycle 0x3000 SECURED). The
/// challenge is host-supplied, so this token is fresh, not a fixed constant.
///
/// Unlike the SiLabs adapter, this test exercises the FULL chain in-EVM: the DUA
/// initial-attestation leaf is verified against the pinned ST CA key, and the EAT
/// against the IAK in that leaf. The STM32 chain is depth 2, so that is two
/// P-256 checks and no off-chain chain walking is trusted.
///
/// The pinned CA key is determined rather than published — the intersection of
/// candidate signers recovered from this die's leaf and the example certificate
/// in UM3254 Rev 8 Figure 7. Fixture in test/fixtures/stm32h5/, regenerable with
/// tools/stm32h5/build_proof.py.
contract Stm32SecureManagerVerifierRealProofTest is Test {
    // ST CA 01 for STM32 Initial Attestation — determined, see contract docs.
    bytes constant ST_CA_PUBKEY =
        hex"04e2a0eda50a72a00249d658c8c147f2d8204ec4d83ed5b304a5d71e861e2ddc961b3015abaa48096df0f2fea52af6566acb9d4355d3b0694dfe38e152bbcebae0";
    // IAK from CN=stm32h5xx-initial_attestation-011700000000001005c2
    bytes constant IAK_PUBKEY =
        hex"04c8522e9e7a08df6885035fdd30099cdfbdf9ac34f10477ac8ca5681360549c9f7d25798ea48ed25c8e1a337a4b4690e0cacae276bdd3eb76c6ae8d2141204968";

    bytes32 constant LEAF_TBS_DIGEST = 0xf2b89f64bdbf52e525cb789a627bae86ce681da980606fee271207bd4bdb3c18;
    bytes32 constant LEAF_R = 0x02d3e69a66a4dbf437ed4d241a5a3d7be3962d16542dc38e309a957f165753ab;
    bytes32 constant LEAF_S = 0xda99c02992de40a4d440eaa23731addaa47f5732436196dd4f995738d4b5f4ad;

    bytes32 constant EAT_DIGEST = 0x1f574fd531f6da8b54e359d772b5ef8a68a3fdf09dca729225a095f15af556a0;
    bytes32 constant EAT_R = 0x7221367f1fb6f35b3ae1662c1a0372585d06a912a9357cd2eb44ea2a411e1ad9;
    bytes32 constant EAT_S = 0x7b06e9be3d1d46e2486ec5884885e2f6e25bdae1858637c985549a0ee8acdaa4;

    // -75006 NSPE: SHA-256 of our own non-secure application, measured by SMuRoT.
    // Reproducible offline from build output — see edge-tee host/nspe_measurement.py.
    bytes32 constant MEASUREMENT = 0x92a7e9ee73c8465e707b3c21fc1c0b09fb605319216a358279ede807f485e071;
    // Host-supplied challenge: the firmware reads 32 random bytes over the console
    // before signing, so the token is fresh rather than a replayable constant.
    bytes constant NONCE = hex"07ca9f122b1882939e63ac253bb07ec939f5118a3daa4b0d4743d396b4a48339";
    uint32 constant LIFECYCLE_SECURED = 0x3000;
    uint32 constant LIFECYCLE_DEBUG = 0x4000;

    bytes32 constant ST_CA_FP = 0xac64f460233e6de4e2b4c5f5080ecaf503067d6aeef540ba76b51d081c12fdc9;

    Stm32SecureManagerVerifier verifier;
    TEEBridge bridge;

    function setUp() public {
        vm.etch(address(0x100), address(new P256Verifier()).code);
        bytes32[] memory cas = new bytes32[](1);
        cas[0] = ST_CA_FP;
        verifier = new Stm32SecureManagerVerifier(cas);
        bridge = new TEEBridge();
    }

    function _proof(uint32 lifecycle, bytes32 eatS, bytes32 leafS)
        internal pure returns (bytes memory)
    {
        return abi.encode(
            Stm32SecureManagerVerifier.Proof({
                stCaPubkeyXY: ST_CA_PUBKEY,
                iakPubkeyXY: IAK_PUBKEY,
                leafTbsDigest: LEAF_TBS_DIGEST,
                leafSig: abi.encodePacked(LEAF_R, leafS),
                cosePayloadDigest: EAT_DIGEST,
                eatSig: abi.encodePacked(EAT_R, eatS),
                measurement: MEASUREMENT,
                nonce: NONCE,
                lifecycle: lifecycle
            })
        );
    }

    function _realProof() internal pure returns (bytes memory) {
        return _proof(LIFECYCLE_SECURED, EAT_S, LEAF_S);
    }

    /// The whole chain verifies in-EVM and yields the identity tuple.
    function test_LiveProofVerifies() public view {
        (bytes32 codeId, bytes memory pubkey, bytes memory userData) = verifier.verify(_realProof());
        assertEq(codeId, MEASUREMENT, "codeId == live NSPE app measurement");
        assertEq(pubkey, IAK_PUBKEY, "pubkey == device IAK");
        assertEq(userData, abi.encode(NONCE, LIFECYCLE_SECURED), "userData == (nonce, lifecycle)");
    }

    /// The live device registers as a TEEBridge member alongside other vendors.
    function test_LiveProofRegistersInBridge() public {
        bridge.addVerifier(address(verifier));
        bridge.addAllowedCode(MEASUREMENT);
        bytes32 memberId = bridge.register(address(verifier), _realProof());
        assertEq(memberId, keccak256(IAK_PUBKEY), "member keyed by keccak256(IAK)");
        assertTrue(bridge.isMember(memberId), "live H573 is a registered member");
        (bytes32 codeId,,,,) = bridge.getMember(memberId);
        assertEq(codeId, MEASUREMENT, "stored codeId == live app measurement");
    }

    /// A part still in TZ-Closed reports 0x4000 and is not code-bound for production.
    function test_NonSecuredLifecycleRejectedByDefault() public {
        assertFalse(verifier.acceptDevMode(), "default policy is strict");
        vm.expectRevert(
            abi.encodeWithSelector(Stm32SecureManagerVerifier.NotSecured.selector, LIFECYCLE_DEBUG));
        verifier.verify(_proof(LIFECYCLE_DEBUG, EAT_S, LEAF_S));
    }

    function test_NonSecuredAcceptedWhenDevModeOn() public {
        verifier.setAcceptDevMode(true);
        (bytes32 codeId,,) = verifier.verify(_proof(LIFECYCLE_DEBUG, EAT_S, LEAF_S));
        assertEq(codeId, MEASUREMENT, "same measurement, weaker posture");
    }

    /// An unpinned CA key is rejected before any signature work.
    function test_UnpinnedCaReverts() public {
        verifier.removeCa(ST_CA_FP);
        vm.expectRevert(
            abi.encodeWithSelector(Stm32SecureManagerVerifier.CaNotAllowed.selector, ST_CA_FP));
        verifier.verify(_realProof());
    }

    /// Tampering the certificate signature breaks the chain to ST — this is the
    /// check the SiLabs adapter delegates off-chain and this one does in-EVM.
    function test_TamperedCertSigReverts() public {
        vm.expectRevert(Stm32SecureManagerVerifier.InvalidCertSignature.selector);
        verifier.verify(_proof(LIFECYCLE_SECURED, EAT_S, bytes32(uint256(LEAF_S) ^ 1)));
    }

    /// Tampering the token signature fails the in-EVM P-256 check.
    function test_TamperedTokenSigReverts() public {
        vm.expectRevert(Stm32SecureManagerVerifier.InvalidTokenSignature.selector);
        verifier.verify(_proof(LIFECYCLE_SECURED, bytes32(uint256(EAT_S) ^ 1), LEAF_S));
    }
}
