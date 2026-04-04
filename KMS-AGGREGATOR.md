# KMS Aggregator: Cross-Instance Key Sharing for dstack on Base

## Problem Statement

Phala Cloud's Base KMS has a fundamental limitation: **you cannot deploy two CVMs with the same `app_id`**. This means two TEE instances running identical code on different machines will derive different keys via `DstackClient.get_key()`, because each gets a unique `app_id`.

This document explains the limitation in detail, how we work around it using TEEBridge, and how to deploy and use the KMS aggregator service so your app gets the same key across any number of CVM instances.

---

## Part A: Phala Cloud API Limitations (Detailed)

### The app_id = identity problem

In dstack, `app_id` is the fundamental identity. When you call `client.get_key("/oracle", "ethereum")`, the KMS derives a key specific to that `app_id`. Two CVMs with the same `app_id` get the same key. Two CVMs with different `app_id`s get different keys.

The `phala deploy` CLI creates a new `app_id` on every deploy. Each `app_id` gets its own `AppAuth` smart contract on Base that controls which compose hashes and devices are allowed.

### Why you can't reuse an app_id

We tried every available path:

1. **Same app_id + same compose_hash via `POST /cvms`**: The API is idempotent — returns the existing CVM instead of creating a second one.

2. **Same app_id + different compose_hash**: Rejected with HTTP 409: `"This app_id already has an active CVM with a different configuration."`

3. **Same app_id + stopped CVM**: Same 409. "Active" means "exists", not "running".

4. **`POST /cvms/{id}/replicas` (Base KMS)**: Returns HTTP 500 Internal Server Error consistently. This is the only sanctioned API path for adding a second CVM to an existing `app_id`. It works on Phala KMS (chain_id=0) but is **broken on Base KMS (chain_id=8453)**.

5. **`phala cvms replicate` CLI**: Same 500 underneath.

### The device_id inconsistency (prod7)

Each Phala Cloud node has a device identity derived from the TDX hardware. The `AppAuth` contract can restrict which devices are allowed to boot a given app. We found that **prod7 has a device_id mismatch**:

| Source | device_id for prod7 |
|--------|-------------------|
| `phala cvms get` (CVM info) | `935b9a1b6438a398...` |
| `phala cvms list-nodes` | `e5a0c70bb6503de2...` |
| KMS at boot time | ??? (rejects the registered ID) |

The `phala deploy --kms base` CLI registers the CVM info device_id on the AppAuth contract, but the KMS passes a different one when calling `isAppAllowed()`. This causes "Boot denied: Device not allowed" even though the contract shows the device as allowed.

**prod5 and prod9 do not have this issue** — per-device allowlisting works correctly on those nodes.

### What allowAnyDevice actually means

The `AppAuth` contract has `setAllowAnyDevice(bool)`. Setting it to `true` skips the device_id check entirely. This is **unacceptable for production** because it allows any TDX device (including potentially compromised hardware) to boot your app and derive keys.

Per-device allowlisting is the correct approach: you explicitly add each physical machine's device_id to your AppAuth contract. This works on prod5 and prod9.

---

## Part B: TEEBridge Workaround

### Architecture

Since we can't give two CVMs the same `app_id`, we give each its own `app_id` and use an on-chain registry (TEEBridge) to:

1. **Verify attestation**: Each CVM proves it's running attested code via the DstackVerifier contract, which checks the KMS signature chain on-chain (secp256k1 ecrecover, ~200K gas).

2. **Share secrets**: Registered members exchange ECIES-encrypted payloads via the TEEBridge `onboard()` function.

```
CVM-A (app_id_X)                    CVM-B (app_id_Y)
  get_key("/oracle")                   get_key("/oracle")
  → different KMS key                  → different KMS key
  → but same TEEBridge-shared key      → same TEEBridge-shared key

        ↕ TEEBridge.sol (Base mainnet) ↕

  KMS Node 1 (prod5)               KMS Node 2 (prod9)
    watches MemberRegistered          watches MemberRegistered
    ECIES-encrypts shared keys        ECIES-encrypts shared keys
    calls onboard()                   calls onboard()
```

### Contracts

Deployed on Base mainnet:

| Contract | Address |
|----------|---------|
| TEEBridge | `0xdf463af67d15e470a363e387fd688c78c2e94146` |
| DstackVerifier | `0x9e3a8b3e3f34c7c527ec8a961e18bbf48359b55c` |

**TEEBridge.sol** is a platform-agnostic registry:
- `register(verifier, proof)` → calls `IVerifier.verifyAndCache(proof)` → stores member with pubkey
- `onboard(from, to, encryptedPayload)` → stores ECIES-encrypted message for recipient
- `addAllowedCode(codeId)` / `addVerifier(verifier)` — admin functions

**DstackVerifier.sol** implements `IVerifier` for dstack:
- Verifies the KMS signature chain: derived_key → app_key → KMS_root
- Uses secp256k1 ecrecover (EVM precompile) — ~200K gas
- `addKmsRoot(address)` — admin adds trusted KMS root addresses

### Registration flow

1. CVM boots, derives a key via real `DstackClient.get_key("/bridge", "ethereum")`
2. Builds a proof: `(messageHash, messageSig, appSig, kmsSig, derivedPubkey, appPubkey, purpose)`
3. Calls `TEEBridge.register(dstackVerifier, abiEncode(codeId, proof))`
4. DstackVerifier verifies on-chain: recovers signers, checks KMS root is allowed
5. TEEBridge stores member with their compressed pubkey
6. Emits `MemberRegistered(memberId, codeId, verifier, pubkey, userData)`

### Onboarding flow

1. KMS node polls for `MemberRegistered` events
2. For each new member: fetches their pubkey via `getMember()`
3. ECIES-encrypts the key store JSON to their pubkey
4. Calls `TEEBridge.onboard(myMemberId, theirMemberId, encrypted)`
5. New member polls `getOnboarding(myMemberId)`, decrypts with their derived key

---

## Part C: KMS Aggregator Service

### Overview

The KMS aggregator consists of:

1. **KMS Nodes** (`bridge_relay.py`) — always-on CVMs that hold the master key store and onboard new members
2. **BridgeDstackClient** (`bridge_client.py`) — drop-in replacement for `DstackClient` that app developers use

### KMS Nodes

We run 2 KMS nodes on different physical machines for high availability:

| Name | Node | app_id | Status |
|------|------|--------|--------|
| kms-1 | prod5 (id=26) | `11b6fdae4d3b5d25f4799cd72425bcef8c1bd5fc` | running |
| kms-2 | prod9 (id=18) | `13c26579e81794293a5117ee643ef0b34bc56dac` | running |

The first KMS node to boot generates the master keys. Subsequent KMS nodes receive them via TEEBridge onboarding from the first.

**Deployment:**

```bash
phala deploy -n kms-1 \
  -c docker-compose.relay.yaml \
  --kms base --private-key $PRIVATE_KEY \
  --node-id 26 \
  -e BRIDGE_CONTRACT=0xdf463af67d15e470a363e387fd688c78c2e94146 \
  -e VERIFIER_CONTRACT=0x9e3a8b3e3f34c7c527ec8a961e18bbf48359b55c \
  -e "RELAY_PRIVATE_KEY=$PRIVATE_KEY" \
  -e 'KEY_PATHS=["/oracle:ethereum"]'
```

The `KEY_PATHS` env var lists which key paths to pre-generate. Format: `["/path:purpose", ...]`.

The `RELAY_PRIVATE_KEY` is a funded Base wallet used to send `onboard()` transactions. This wallet must be the owner of the TEEBridge and DstackVerifier contracts (for auto-adding code IDs and KMS roots).

**What KMS nodes do at startup:**
1. Derive identity from real KMS (`get_key("/bridge", "ethereum")`)
2. Self-register on TEEBridge
3. Check if another KMS node already onboarded us → use those keys
4. Otherwise generate fresh keys for each path in `KEY_PATHS`
5. Catch up: scan recent `MemberRegistered` events, onboard any un-onboarded members
6. Poll for new members every 10 seconds

**Endpoints:**
- `GET /status` — JSON with member_id, key paths, onboarded count
- `GET /proof` — attestation proof for this KMS node

### BridgeDstackClient (Drop-in Replacement)

App developers replace `DstackClient()` with `BridgeDstackClient(...)`:

```python
# Before (only works with single app_id):
from dstack_sdk import DstackClient
client = DstackClient()
result = client.get_key("/oracle", "ethereum")

# After (works across any number of app_ids):
from bridge_client import BridgeDstackClient
client = BridgeDstackClient(
    bridge="0xdf463af67d15e470a363e387fd688c78c2e94146",
    verifier="0x9e3a8b3e3f34c7c527ec8a961e18bbf48359b55c",
    private_key=os.environ['APP_PRIVATE_KEY'],
)
result = client.get_key("/oracle", "ethereum")
# result.key is the same hex string regardless of which CVM you're on
```

**What happens on first `get_key()` call:**
1. Derives identity from real KMS (for attestation proof)
2. Registers on TEEBridge (auto-adds KMS root and code ID if needed)
3. Polls `getOnboarding()` until a KMS node sends the key store (~5-30 seconds)
4. Caches all keys in memory
5. Returns the requested key

Subsequent `get_key()` calls return from cache instantly.

**Return type:** `BridgeKeyResponse` with `.key` (hex string) and `.signature_chain` (empty list). The `.key` field is the same format as `GetKeyResponse.key` from the real SDK.

**`info()`** delegates to the real `DstackClient.info()` — returns the actual app_id, compose_hash, etc.

### Deploying an App

```bash
phala deploy -n my-app \
  -c docker-compose.demo.yaml \
  --kms base --private-key $PRIVATE_KEY \
  --node-id 26 \
  -e BRIDGE_CONTRACT=0xdf463af67d15e470a363e387fd688c78c2e94146 \
  -e VERIFIER_CONTRACT=0x9e3a8b3e3f34c7c527ec8a961e18bbf48359b55c \
  -e "APP_PRIVATE_KEY=$PRIVATE_KEY"
```

The `APP_PRIVATE_KEY` needs to be funded on Base to pay for registration transactions (~500K gas for addAllowedCode + register).

### Verified Demo Results

Two demo apps deployed on different machines both received the same key:

```
demo-a (prod5): oracle_signer=0xEBe0c9a39b9C4c7E7099ca1a7DD6ceEFd072fd86, key_prefix=0x22d423c04e20a236...
demo-b (prod9): oracle_signer=0xEBe0c9a39b9C4c7E7099ca1a7DD6ceEFd072fd86, key_prefix=0x22d423c04e20a236...
```

Different app_ids, different physical machines, per-device allowlisting, same derived key.

---

## File Reference

| File | Purpose |
|------|---------|
| `bridge_relay.py` | KMS node service (always-on, onboards new members) |
| `bridge_client.py` | Drop-in `DstackClient` replacement for app developers |
| `docker-compose.relay.yaml` | Compose for KMS nodes (uses pinned Docker image) |
| `docker-compose.demo.yaml` | Compose for demo app (inlines bridge_client.py) |
| `Dockerfile.relay` | Dockerfile for KMS node image |
| `contracts/TEEBridge.sol` | Registry + onboarding contract |
| `contracts/DstackVerifier.sol` | On-chain dstack attestation verification |
| `register.py` | Standalone registration script (for manual use) |
| `onboard.py` | Standalone onboarding script (for manual use) |

## Known Issues

1. **prod7 device_id mismatch**: Per-device allowlisting fails on prod7 due to inconsistent device_id reporting. Use prod5 and prod9 instead.

2. **Shared deployer wallet**: If multiple KMS nodes use the same `RELAY_PRIVATE_KEY`, they can have nonce races when onboarding the same member simultaneously. The current code handles this by checking if onboarding already exists before sending. For production, each KMS node should have its own funded wallet.

3. **On-chain onboarding latency**: The `BridgeDstackClient` polls on-chain every 3 seconds for up to 120 seconds. KMS nodes poll for new members every 10 seconds. Total onboarding latency is typically 15-30 seconds. A direct TLS endpoint on KMS nodes would reduce this to <1 second.

4. **Base RPC rate limits**: The free `https://mainnet.base.org` endpoint rate-limits at ~50 req/s. Use a dedicated RPC provider for production.

## Future: TLS-Based Onboarding

The on-chain onboarding path works but adds latency and gas costs. A faster alternative: KMS nodes expose a `/onboard` HTTPS endpoint where a registered member can POST their member_id and receive the ECIES-encrypted key store directly over TLS. The on-chain path remains as a fallback for censorship-resistant scenarios (e.g., KMS nodes behind Tor).
