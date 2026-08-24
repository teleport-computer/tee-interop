# Heterogeneous TEE interop: two edge MCUs + a datacenter CVM

Three different-vendor TEEs registered as peers in one on-chain registry on **Base Sepolia**
(chain 84532), each verified by its own `IVerifier` module. Live 2026-08-23.

Supersedes `INTEROP-silabs-dstack.md`, which covered the first two.

## Deployed (Base Sepolia)

| Contract | Address |
|---|---|
| TEEBridge | `0x31F8e4cf395dcffc6596AE31885FD1E73d6932fa` |
| SilabsVerifier | `0x857A6E8810E30e63f5B544180E2F5a139d50351b` |
| DstackVerifier | `0x296845C8784abd5F9e329C9d8DDd849064057C65` |
| **Stm32SecureManagerVerifier** | **`0x1a95113805166A856c2C78290f268BFCbBEa8128`** |

## Members

| Member | codeId | Verifier | Root anchor |
|---|---|---|---|
| **STM32H573** (edge MCU, H573I-DK) | `0x92a7e9ee…f485e071` (**NSPE** = app SHA-256, PRODUCT_STATE Closed) | Stm32SecureManagerVerifier | ST init-attest CA `ac64f460…` — *determined*, see below |
| **SiLabs SiMG301** (edge MCU, BRD2719A) | `0x9aeba9ff…662efe5e` (**ARoT** = app SHA-256, secure boot ON) | SilabsVerifier | SiLabs Device Root CA `dbf5f0b3…` — published |
| **dstack tee-daemon** (Phala TDX CVM) | `0x915c8197…` (CVM app-id) | DstackVerifier | Phala KMS root `0xd5bdeb03…` |

Member ids: H573 `0x597b34c9…`, SiLabs `0x4af324d3…`, dstack `0x63ca2560…`.
All three `TEEBridge.isMember(...) == true`.

## Why this is any-to-any, not three pairings

`TEEBridge.onboard(fromMemberId, toMemberId, encryptedPayload)` takes *any* two member ids.
Nothing is wired pairwise. Verification is factored per **vendor**, not per **pair**: N platforms
need N `IVerifier` modules, not N² bridges, because every module reduces its vendor's native
evidence to the same triple —

    (codeId, pubkey, userData)

— so a member that has never heard of STM32 can still check an H573 peer's code identity. Three is
the number of parts we have done hardware bring-up on, not a property of the design.

**What actually limits the count is trust anchors, not the contract.** Surveying 60+ PSA Level 2+
products, exactly one vendor (Silicon Labs) publishes a clean public device root. That is the
scarce resource. The STM32 entry widens the admissible set, because it shows a *licence-gated*
anchor can still be brought in — by determination from public material rather than vendor
cooperation.

**Honest limit:** `addVerifier` and `addAllowedCode` are `onlyOwner`. Messaging among members is
any-to-any; *admission* is still permissioned. Making admission permissionless — anyone may
register a vendor module against a published anchor — is the remaining step toward the
permissionless registry.

## The STM32 anchor is determined, not published

ST delivers the initial-attestation CA certificate under licence (UM3254 Rev 8 §11.1.1), so unlike
Silicon Labs there is no root to download. A P-256 signature plus its message pins the signer to
two candidates; intersecting the candidate pairs from two independent leaves leaves exactly one.
The two leaves used were a die we own and the example certificate ST printed in **UM3254 Rev 8
Figure 7**. Both halves are reproducible by anyone with the (free) user manual and any STM32H573.

The intersection self-validates: one wrong byte changes the digest, changes the recovered keys, and
the sets go disjoint.

## The STM32 adapter verifies its whole chain on-chain

`SilabsVerifier` pins a root fingerprint and trusts the off-chain builder to have walked
SE → Batch → Factory → Device Root — four hops is too much for the EVM. The STM32 DUA chain is
**depth 2**, so `Stm32SecureManagerVerifier` does both hops itself via RIP-7212:

1. `leafSig` over `leafTbsDigest` under the pinned ST CA key → the IAK really was certified by ST
2. `eatSig` over `cosePayloadDigest` under that IAK → the token really came from that device

No off-chain chain walk is trusted. Verified live:

```
$ cast call 0x1a95113805166A856c2C78290f268BFCbBEa8128 \
    "verify(bytes)(bytes32,bytes,bytes)" <proof> --rpc-url https://sepolia.base.org
0x92a7e9ee73c8465e707b3c21fc1c0b09fb605319216a358279ede807f485e071   # app measurement
0x04c8522e…04968                                                     # device IAK
nonce 07ca9f12…  lifecycle 0x3000 SECURED
```

## How each proof is produced (self-contained)

**STM32H573** — `tools/stm32h5/build_proof.py`. The DUA init-attest leaf is reconstructed from a
512-byte SWD read of PACK1 (`0x0BF9FE00`) — no firmware, no Secure Manager, no CubeProgrammer. The
EAT comes off the console; the firmware takes a 32-byte host nonce before signing, so the token is
fresh rather than a replayable constant. Policy is strict: PSA lifecycle must be `0x3000` SECURED,
since the NSPE measurement is not production-trustworthy in TZ-Closed.

The measurement is reproducible offline from build output —
`SHA256(header ‖ app.bin ‖ zero-pad ‖ protected_tlvs)`, the region MCUboot signs. Demonstrated by
changing the app: adding host-nonce support moved the measurement from `0effd524…` to `92a7e9ee…`,
and the verifier rejected the stale value.

**SiLabs / dstack** — unchanged, see `INTEROP-silabs-dstack.md`.

## Reproduce / inspect

```bash
# all three members live
cast call 0x31F8e4cf395dcffc6596AE31885FD1E73d6932fa "isMember(bytes32)(bool)" \
  0x597b34c97bba368044847a3db34f544d914bac0af2292af85c1ad6ef1007f63a \
  --rpc-url https://sepolia.base.org

# rebuild the STM32 proof from hardware artifacts
python3 tools/stm32h5/build_proof.py eat.hex leaf.pem ca_pub.pem -o proof.json

# in-EVM tests (needs --via-ir: the vendored P256Verifier blows the stack otherwise)
forge test --via-ir --match-contract Stm32SecureManagerVerifierRealProof
```
