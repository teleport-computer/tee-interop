# TEEBridge: Multi-Verifier TEE Membership Registry

TEEBridge is a platform-agnostic registry where TEE-attested identities from **different platforms** register as peers and share secrets via ECIES-encrypted onboarding. Each attestation platform (dstack, GitHub/Sigstore, Nitro, TDX, etc.) plugs in as an `IVerifier` — the registry has zero platform-specific code.

## The Interface (ERC-733)

> Part of the ongoing input process for ERC-8004 (TEE attestation standards). See [Relationship to Sparsity 8004 POC](#relationship-to-sparsity-8004-poc) for how we compare to the existing reference implementation.

```solidity
interface IVerifier {
    /// Pure verification — no state changes
    function verify(bytes calldata proof) external view
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);

    /// Verification with optional caching (e.g. Nitro cert chain)
    function verifyAndCache(bytes calldata proof) external
        returns (bytes32 codeId, bytes memory pubkey, bytes memory userData);
}
```

Each verifier decodes its own proof format from opaque `bytes`. Returns three things:
- **`codeId`** — code identity (compose hash, PCR0, commit SHA, etc.)
- **`pubkey`** — member's public key for ECIES encryption
- **`userData`** — arbitrary attestation-embedded data (e.g. an Ethereum address, reportData)

The `verify`/`verifyAndCache` split keeps the interface `view`-clean while supporting verifiers that benefit from caching (like Nitro's P-384 x509 chain — 56M gas cold, 18M warm). The registry calls `verifyAndCache` during registration; `verify` exists for off-chain reads and view-compatible verifiers.

## Architecture

```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  dstack CVM     │  │  dstack CVM     │  │  GitHub Action  │
│  Phala Cloud    │  │  self-hosted     │  │  Sigstore       │
│  Base KMS       │  │  Sepolia KMS    │  │  ZK proof       │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │ register.py        │ register.py         │ (future)
         ▼                    ▼                     ▼
┌──────────────────────────────────────────────────────────────┐
│  TEEBridge.sol — platform-agnostic registry                  │
│  register(verifier, proof) → IVerifier.verifyAndCache()      │
│  allowedVerifiers, allowedCode, members, onboarding          │
├──────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌──────────────────┐                   │
│  │ DstackVerifier   │  │ SigstoreAdapter  │  ← IVerifier     │
│  │ KMS chain verify │  │ ZK proof verify  │                   │
│  └─────────────────┘  └──────────────────┘                   │
└──────────────────────────────────────────────────────────────┘
```

### Registration Flow

1. **CVM** runs Flask server exposing `/proof` with platform-specific proof JSON
2. **External script** (`register.py`) fetches proof, calls `TEEBridge.register(verifier, encodedProof)`
3. **TEEBridge** delegates to `IVerifier(verifier).verifyAndCache(proof)` → gets `(codeId, pubkey, userData)`
4. **TEEBridge** checks `allowedCode[codeId]`, stores member with `verifier` and `userData` fields
5. `MemberRegistered(memberId, codeId, verifier, pubkey, userData)` emitted — filterable by platform

### Onboarding: ECIES Secret Sharing

Members exchange ECIES-encrypted secrets via `onboard()`. This is the layer that makes TEEBridge useful beyond just a registry — attested enclaves from different platforms can share secrets without any shared KMS infrastructure.

```
CVM-A (dstack, Phala)  ──onboard(encrypted)──▶  TEEBridge  ──▶  CVM-B (Nitro, AWS)
                                                                   └─ decrypts with
                                                                      KMS-derived key
```

## Contract Layout

| File | Role |
|------|------|
| `IVerifier.sol` | The interface (ERC-733) |
| `TEEBridge.sol` | Platform-agnostic registry + ECIES onboarding |
| `DstackVerifier.sol` | dstack KMS signature chain verification |
| `SigstoreAdapter.sol` | GitHub/Sigstore ZK proof verification |
| `ISigstoreVerifier.sol` | Interface for deployed Sigstore ZK verifier |

## Verifier Status

| Platform | Status | Contract / Reference | Attestation | On-Chain Verification | Gas |
|----------|--------|---------------------|-------------|----------------------|-----|
| **dstack** (Phala, self-hosted) | **Done** | `DstackVerifier.sol` | KMS sig chain (secp256k1) | 3x ecrecover + secp256k1 decompress | ~200K |
| **GitHub/Sigstore** | **Adapter written** | `SigstoreAdapter.sol` | ZK proof of Sigstore cert chain | Wraps Noir verifier on Base (`0x904A...`) | ~300K |
| **AWS Nitro** | **Reference exists** | [Sparsity POC](https://github.com/sparsity-xyz/8004-tee-registry-ri), [Marlin Oyster](https://github.com/marlinprotocol/oyster-contracts) | COSE Sign1, P-384, x509 | Pure Solidity P-384 + cert caching (Sparsity), or direct PCR verification (Marlin). `codeId` = `keccak256(PCR0‖PCR1‖PCR2)` | ~18M warm |
| **Intel TDX/SGX** (DCAP) | **Reference exists** | [Sparsity POC](https://github.com/sparsity-xyz/8004-tee-registry-ri), [Automata DCAP](https://github.com/automata-network/automata-dcap-attestation) | DCAP quote (P-256) | Automata `verifyAndAttestOnChain()` or ZK-wrapped. `codeId` = `keccak256(MRENCLAVE‖MRSIGNER)` | ~4-5M |
| **AMD SEV-SNP** | **Reference exists** | [Automata SEV-SNP SDK](https://github.com/automata-network/amd-sev-snp-attestation-sdk) | SEV-SNP report + VEK cert chain | ZK-wrapped (Risc0/SP1/Pico) via `SEVAgentAttestation.sol`. `codeId` = launch measurement | ~varies |
| **Secret Network** (SecretVM) | **Not started** | — | Intel SGX (EPID/DCAP), Cosmos consensus-layer | Attestation baked into Cosmos validator registration. No standalone EVM verifier — would need cross-chain bridge (IBC?) or reuse Automata DCAP for raw SGX quotes | N/A |
| **Marlin Oyster** | **Reference exists** | [Oyster contracts](https://github.com/marlinprotocol/oyster-contracts) | AWS Nitro (PCR0/1/2) | `AttestationVerifier.sol` on Arbitrum Sepolia. Clean pattern: verify once, whitelist enclave pubkey | ~TBD |
| **Lit Protocol** | **Not started** | — | AMD SEV-SNP | Own attestation service on Chronicle L2. No reusable EVM verifier | N/A |
| **Google Confidential Space** | **Not started** | — | SEV-SNP or TDX (via vTPM) | Centralized Google Cloud Attestation API only. Could extract raw reports and use Automata verifiers | N/A |
| **Oasis ROFL** | **Not started** | — | Runtime-verified, `bytes21` app ID | Sapphire precompile only. Cross-chain needs attestation bridging | N/A |
| **ARM CCA** | **Not started** | — | CCA token (COSE, EAT) | No known on-chain verifier. Similar to Nitro — P-256/P-384 + CBOR | TBD |

**Want to add your platform?** Implement `IVerifier` and open a PR. See [Adding a New Platform](#adding-a-new-platform).

## Relationship to Sparsity 8004 POC

The [Sparsity `8004-tee-registry-ri`](https://github.com/sparsity-xyz/8004-tee-registry-ri) is a working multi-verifier TEE registry deployed on Base Sepolia with Nitro and TDX verifiers. Our interfaces are converging — here are the intentional differences:

| | Sparsity POC | TEEBridge |
|---|---|---|
| **`verify()` mutability** | Non-view only (Nitro cert caching mutates state) | `verify()` is `view`; `verifyAndCache()` is non-view. Caching is opt-in, not forced on view-compatible verifiers |
| **Onboarding layer** | Registry only — no secret sharing | **ECIES onboarding built in.** Members encrypt secrets to each other's registered pubkeys on-chain. This is the key layer for cross-platform secret sharing without shared KMS |
| **Verifier selection** | Caller passes `TEEType` enum | Caller passes verifier contract address. More flexible — new platforms don't need enum updates |
| **Code allowlisting** | `whitelistMeasurement(bytes32, string)` with source URL | `addAllowedCode(bytes32)` — simpler, source linking is off-chain |
| **Return values** | `(codeMeasurement, pubKey, userData)` | Same — `(codeId, pubkey, userData)` |

The core `IVerifier` interface is compatible. The main value-add of TEEBridge over the Sparsity registry is the **onboarding layer** — without it, registered members have no way to actually share secrets.

## Quick Start

### 1. Deploy

```bash
forge install foundry-rs/forge-std

# Deploy with dstack KMS root + optional Sigstore verifier
KMS_ROOTS=0x52d3CF51... SIGSTORE_VERIFIER=0x904Ae91... \
  forge script script/Deploy.s.sol \
  --broadcast --rpc-url https://mainnet.base.org --private-key $KEY
```

### 2. Deploy a CVM

```bash
# Phala Cloud
phala deploy --name my-bridge --compose docker-compose.yaml \
  --image dstack-0.5.4 --node-id 26 \
  --kms base --private-key $KEY --rpc-url https://mainnet.base.org
```

### 3. Register

```bash
# --verifier is the DstackVerifier contract address
python3 register.py --cvm-url https://APP_ID-8080.gateway.domain \
  --bridge $BRIDGE --verifier $DSTACK_VERIFIER --private-key $KEY

# Or from serial logs:
python3 register.py --proof-json '{"code_id":"0x...","dstack_proof":{...}}' \
  --bridge $BRIDGE --verifier $DSTACK_VERIFIER --private-key $KEY
```

`register.py` auto-adds the KMS root (on DstackVerifier) and code ID (on TEEBridge) if needed.

### 4. Send a Secret

```bash
python3 onboard.py \
  --from-member 0xaaa... --to-member 0xbbb... \
  --secret "shared secret" \
  --bridge $BRIDGE --private-key $KEY
```

### 5. Receive Secrets

- **Polling**: Set `BRIDGE_CONTRACT` env var — agent polls every 60s
- **HTTP**: `GET /onboarding?bridge=0x...` returns decrypted messages

## Verification Approaches: ZK vs Direct On-Chain

The `IVerifier` interface is agnostic to how verification happens internally. In practice there are three tiers:

**Native EVM crypto (cheapest, no ZK)**
| Verifier | Crypto | Gas | Why it's cheap |
|----------|--------|-----|---------------|
| dstack | secp256k1 ecrecover | ~200K | EVM precompile |
| Intel TDX/SGX (DCAP) | ECDSA P-256 | ~4-5M | RIP-7212 precompile on Base/OP |

**ZK-wrapped (medium cost, universal)**
| Verifier | Proof System | Verifier Gas | Confirmed? |
|----------|-------------|-------------|------------|
| Sigstore ([github-zktls](https://github.com/anthropics/github-zktls)) | Noir / UltraHonk | **~2.83M** | Yes — [gas analysis](https://github.com/anthropics/github-zktls/blob/main/docs/gas-analysis.md) |
| AMD SEV-SNP ([Automata](https://github.com/automata-network/amd-sev-snp-attestation-sdk)) | SP1 → Groth16 | **~293-315K** | Yes — Sepolia txns |
| AMD SEV-SNP (Automata) | Risc0 → Groth16 | **~250-270K** | Estimated (no txns yet) |

**Direct on-chain (expensive, no trusted setup)**
| Verifier | Crypto | Gas |
|----------|--------|-----|
| AWS Nitro ([Sparsity](https://github.com/sparsity-xyz/8004-tee-registry-ri)) | P-384 ECDSA in Solidity + cert caching | ~18M warm, ~56M cold |

**Why is Groth16 10x cheaper than UltraHonk?** Groth16 verification is a single pairing check (~181-362K gas). UltraHonk verification requires Shplemini polynomial commitment checks (62-point MSM + fold + pairing) at ~2.83M gas. The tradeoff: Groth16 needs a trusted setup per-circuit and proving is slower; UltraHonk has no trusted setup and faster proving. For attestation verification where the circuit is stable, Groth16's gas advantage matters.

**zkVM vs circuit DSL:** Risc0/SP1 let you write verification logic in Rust and get a Groth16 proof. Noir requires rewriting as a circuit. For complex verification (CBOR parsing, x509 chains, P-384), the zkVM path is significantly less development effort. The `IVerifier` interface doesn't care which approach a verifier uses — this is an implementation choice per platform.

## Adding a New Platform

Implement both functions from `IVerifier`:

1. **`verify(bytes proof)`** (`view`) — decode your proof format, verify attestation, return `(codeId, pubkey, userData)`. Revert on failure.
2. **`verifyAndCache(bytes proof)`** — if your verification benefits from caching (like Nitro's cert chain), do it here. Otherwise just delegate to `verify()`.
3. Deploy and call `bridge.addVerifier(yourVerifier)`

## Reference Deployments

- **TEEBridge** on Base mainnet: [`0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5`](https://basescan.org/address/0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5) (previous single-verifier version)
- **Sparsity TEE Registry** on Base Sepolia: [`0xf08d07b09c33535dcc4c3bae04ccc5466e9297ee`](https://sepolia.basescan.org/address/0xf08d07b09c33535dcc4c3bae04ccc5466e9297ee) (Nitro + TDX, no onboarding)
