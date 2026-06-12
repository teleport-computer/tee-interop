# Heterogeneous TEE interop: SiLabs edge MCU ↔ dstack Phala CVM

Two different-vendor TEEs registered as peers in one on-chain registry on **Base Sepolia**
(chain 84532), each verified by its own `IVerifier` module. Live 2026-06-12.

## Deployed (Base Sepolia)

| Contract | Address |
|---|---|
| TEEBridge | `0x46f9bF18AE0caeF4C4b78c6aAb4064a8a7504d18` |
| SilabsVerifier | `0x857A6E8810E30e63f5B544180E2F5a139d50351b` |
| DstackVerifier | `0x296845C8784abd5F9e329C9d8DDd849064057C65` |

## Members

| Member | codeId | Verifier | Root anchor |
|---|---|---|---|
| **SiLabs SiMG301** (edge MCU, BRD2719A) | `0x830385b8…c42fe6` (PRoT measurement) | SilabsVerifier | SiLabs Device Root CA `dbf5f0b3…` |
| **dstack tee-daemon** (Phala TDX CVM) | `0x915c8197…` (CVM app-id) | DstackVerifier | Phala KMS root `0xd5bdeb03…` |

Both `TEEBridge.isMember(...) == true`. Member ids:
- SiLabs `0x4af324d3…`, dstack `0x63ca2560…`.

## How each proof is produced (self-contained)

**SiLabs side** — `tools/silabs/build_proof.py`: pulls the live PSA IAT (COSE_Sign1/ES256) off the
SiMG301 over VCOM, verifies the full SE→Batch→Factory→Device-Root-CA chain offline, reconstructs the
COSE Sig_structure digest. On-chain: `SilabsVerifier` re-checks the ES256 sig via Base's native RIP-7212
P256 precompile (`0x100`) + root allowlist + dev-mode policy.

**dstack side** — `bridge_agent.py`, a small tee-interop app that runs *inside* any dstack CVM (hosted by
tee-daemon as just another tenant — it needs nothing added to the daemon core). From the CVM's dstack KMS
`get_key("/bridge","ethereum")` it assembles a `DstackProof` (KMS→app→derived-key signature chain +
EIP-191 ownership) and serves it at `/proof`. On-chain: `DstackVerifier` recovers the chain
(ecrecover/modexp) and checks the KMS root is allowlisted. The derived **private key stays inside the CVM**
— only signatures leave.

## Reproduce / inspect

```bash
# show both members live
BRIDGE=0x46f9bF18AE0caeF4C4b78c6aAb4064a8a7504d18
RPC=https://sepolia.base.org
cast call --rpc-url $RPC $BRIDGE 'isMember(bytes32)(bool)' 0x4af324d332bb7844d16c9aac396245414edb1d477fae21d900bfc8df203b1718  # SiLabs
cast call --rpc-url $RPC $BRIDGE 'isMember(bytes32)(bool)' 0x63ca256008edd395c03f57e4086c0417e19e19bf2ba7cab218e112b2c6b37307  # dstack
```

## Caveat (member 2)

The dstack member-2 proof was produced from a project key obtained via a tee-daemon private-key leak
(`/_api/attest` returned the dstack GetKey *private* key publicly; fixed in tee-daemon with a minimal
server-side pubkey-derivation patch — no new dependency). The attestation chain is genuine (real
Phala-KMS-rooted CVM identity), but until the fix is deployed and member 2 is re-registered from the
in-CVM `/bridge` key (via the `bridge_agent` app), member 2's key was not secret. The SiLabs member is
fully clean.
