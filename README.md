# TEEBridge: Multi-Verifier TEE Membership Registry

TEEBridge is a platform-agnostic registry where TEE-attested identities from **different platforms** register as peers and share secrets via ECIES-encrypted onboarding. Each attestation platform (dstack, GitHub/Sigstore, etc.) plugs in as an `IVerifier` — the registry has zero platform-specific code.

## The Interface

> **Note:** We initially called this "ERC-8004" but that EIP covers AI agent identity. This interface is a candidate for a new EIP — a standard for pluggable TEE attestation verification on EVM.

```solidity
interface IVerifier {
    function verify(bytes calldata proof) external view returns (bytes32 codeId, bytes memory pubkey);
}
```

Each verifier decodes its own proof format from opaque `bytes`. Returns the two things the registry needs: **code identity** and **member pubkey**.

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
│  register(verifier, proof) → IVerifier(verifier).verify()    │
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
3. **TEEBridge** delegates to `IVerifier(verifier).verify(proof)` → gets `(codeId, pubkey)`
4. **TEEBridge** checks `allowedCode[codeId]`, stores member with `verifier` field
5. `MemberRegistered(memberId, codeId, verifier, pubkey)` emitted — filterable by platform

### Onboarding (unchanged)

Members exchange ECIES-encrypted secrets via `onboard()`. Platform-agnostic — any member can onboard any other member.

## Contract Layout

| File | Role |
|------|------|
| `IVerifier.sol` | The interface (candidate EIP) |
| `TEEBridge.sol` | Platform-agnostic registry + onboarding |
| `DstackVerifier.sol` | dstack KMS signature chain verification |
| `SigstoreAdapter.sol` | GitHub/Sigstore ZK proof verification |
| `ISigstoreVerifier.sol` | Interface for deployed Sigstore ZK verifier |

## Verifier Status

| Platform | Status | Contract | Attestation Format | On-Chain Verification |
|----------|--------|----------|-------------------|----------------------|
| **dstack** (Phala, self-hosted) | **Done** | `DstackVerifier.sol` | KMS signature chain (secp256k1) | Native — 3 ecrecover + secp256k1 decompression |
| **GitHub/Sigstore** | **Adapter written** | `SigstoreAdapter.sol` | ZK proof of Sigstore certificate chain | Wraps deployed Noir verifier on Base (`0x904A...`) |
| **AWS Nitro** | **Not started** | — | COSE Sign1, P-384 ECDSA, x509 cert chain | P-384 not native to EVM. Needs Noir ZK proof (same pattern as Sigstore) or raw P-384 impl (~expensive). `codeId` = PCR0 |
| **Intel TDX** (raw, non-dstack) | **Not started** | — | SGX/TDX quote (ECDSA P-256) | P-256 available via RIP-7212 on some chains. Automata Network has [on-chain verifiers](https://github.com/automata-network/automata-dcap-attestation). `codeId` = MRTD/RTMR |
| **Oasis ROFL** | **Not started** | — | Runtime-verified, `bytes21` app ID | Only works on Sapphire via `roflEnsureAuthorizedOrigin()` precompile. Cross-chain would need attestation bridging — different architecture |
| **ARM CCA** | **Not started** | — | CCA attestation token (COSE, EAT) | Similar to Nitro — needs ZK proof or native COSE/P-256 verification |

**Want to add your platform?** Implement `IVerifier.verify(bytes proof) → (bytes32 codeId, bytes pubkey)` and open a PR. See [Adding a New Platform](#adding-a-new-platform) below.

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

## Adding a New Platform

Implement `IVerifier.verify(bytes proof) → (bytes32 codeId, bytes pubkey)`:

1. Define your proof encoding (abi.encode whatever your platform needs)
2. Verify attestation inside `verify()` — revert on failure
3. Return `codeId` (code identity hash) and `pubkey` (member's compressed public key)
4. Deploy and call `bridge.addVerifier(yourVerifier)`

## Reference Deployment

TEEBridge on **Base mainnet**: [`0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5`](https://basescan.org/address/0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5) (previous single-verifier version)
