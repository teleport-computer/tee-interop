# KMS Aggregator: Cross-Instance Key Sharing for dstack on Base

## Problem Statement

Phala Cloud's native replication (`POST /cvms/{uuid}/replicas`) works for deploying multiple CVMs with the same `app_id` on Base KMS — **when you use working nodes** (prod5, prod9). However, the tooling around it is fragile:

- The `phala cvms replicate` CLI (v1.1.13) is broken for Base KMS (validation errors, can't resolve CVM names/UUIDs)
- prod7 has a device ID mismatch that breaks per-device allowlisting entirely
- There is no CLI support for adding device IDs to AppAuth contracts — you need raw contract calls

For the simple case (same code on 2-3 nodes), **use the native replicas API directly** — see [TWO-NODE-CLUSTER.md](TWO-NODE-CLUSTER.md).

The **KMS aggregator** (TEEBridge) solves a different problem: letting **multiple independent applications with different compose hashes** share the same derived keys. This is useful when:

- You run a key management service for other app developers
- Multiple apps (different code, different app_ids) need access to the same signing key
- You want cross-platform key sharing (dstack + GitHub Actions + Nitro, etc.)

---

## Part A: Phala Cloud Operational Notes

### Native replication (the simple path)

Deploying 2 nodes with the same `app_id` works via the REST API:

1. `phala deploy --node-id 26 --kms base` (deploy on prod5)
2. `addDevice(prod9_device_id)` on the AppAuth contract
3. `POST /api/v1/cvms/{uuid}/replicas` with `{"teepod_id": 18}` (prod9)

Both instances derive the same key from `getKey()`. See [TWO-NODE-CLUSTER.md](TWO-NODE-CLUSTER.md) for the full procedure.

### Node-specific issues

**prod7 (node-id 12) is broken.** It has a device ID mismatch — three different sources report three different device IDs:

| Source | device_id for prod7 |
|--------|-------------------|
| `phala cvms get` (CVM info) | `935b9a1b6438a398...` |
| `phala cvms list-nodes` | `e5a0c70bb6503de2...` |
| KMS at boot time | ??? (rejects both) |

Per-device allowlisting always fails on prod7. The only workaround is `setAllowAnyDevice(true)`, which is unacceptable for production because it disables hardware attestation of the physical machine.

**prod5 (node-id 26) and prod9 (node-id 18) work correctly.** Per-device allowlisting, native replication, and the replicas API all function as expected on these nodes.

### CLI bugs (v1.1.13)

- `phala cvms replicate <name>` — "CVM not found"
- `phala cvms replicate <uuid>` — "CVM not found"
- `phala cvms replicate <app_id>` — validation error (missing fields)

The REST API works fine. Use `POST /api/v1/cvms/{vm_uuid}/replicas` directly.

### Do not use allowAnyDevice

The `AppAuth` contract has `setAllowAnyDevice(bool)`. Setting it to `true` skips the device_id check entirely. This is **unacceptable for production** because it allows any TDX device (including potentially compromised hardware) to boot your app and derive keys.

Per-device allowlisting is the correct approach: explicitly add each physical machine's device_id to your AppAuth contract.

| Node | node-id | Device ID |
|------|---------|-----------|
| prod5 | 26 | `c4691f9c88f44e05cbc45521678e72b99fcd54fa35d302f13e8f9fa9727f33a6` |
| prod9 | 18 | `573f4908a95b4159c4c262fc8244a485a77d874dc4b1bdf28d38afe80ca77431` |

---

## Part B: TEEBridge — Cross-App Key Sharing

### Why not just use native replication?

For most cases within Phala Cloud, you should. Native replication via `POST /replicas` handles same-code and different-code replicas (you can add multiple compose hashes to one AppAuth contract). It's simpler and doesn't require extra infrastructure.

TEEBridge adds value in narrower scenarios:

- **Cross-platform attestation** — dstack, GitHub Actions (Sigstore), AWS Nitro, and Intel TDX instances sharing secrets, verified by platform-specific on-chain verifiers
- **Independent operators** — parties who don't share a Phala Cloud account and can't coordinate on a single app_id
- **Resilience** — a fallback if Phala's CLI/API has issues on specific nodes (as we saw with prod7)

### Architecture

Each CVM gets its own `app_id` and uses an on-chain registry (TEEBridge) to:

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
