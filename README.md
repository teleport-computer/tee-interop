# TEEBridge: Cross-KMS Secret Sharing for dstack CVMs

TEEBridge lets dstack CVMs running on **different KMS ecosystems** verify each other's attestations and share secrets through a single smart contract. A CVM on Phala Cloud (Base KMS) and a CVM on a self-hosted dstack instance (Sepolia KMS) can become members of the same bridge and exchange ECIES-encrypted onboarding payloads — no shared KMS infrastructure required.

## How It Works

```
┌─────────────────┐         ┌──────────────────┐
│  CVM-A          │         │  CVM-B           │
│  Phala Cloud    │         │  self-hosted     │
│  Base KMS       │         │  Sepolia KMS     │
│                 │         │                  │
│  Flask :8080    │         │  Flask :8080     │
│  GET /proof     │         │  GET /proof      │
│  GET /info      │         │  GET /onboarding │
└────────┬────────┘         └────────┬─────────┘
         │                           │
         │  register.py              │  register.py
         │  (fetches /proof,         │  (fetches /proof,
         │   submits tx)             │   submits tx)
         │                           │
         └──────────┐   ┌────────────┘
                    ▼   ▼
            ┌───────────────────┐
            │  TEEBridge.sol    │
            │  Base Mainnet     │
            │                   │
            │  allowedKmsRoots  │
            │  allowedCode      │
            │  members          │
            │  onboarding msgs  │
            └───────────────────┘
                    ▲
                    │
              onboard.py
              (ECIES encrypt,
               submit tx)
```

### The 3-Step Signature Chain

Every dstack CVM gets a KMS-derived key with a **signature chain** proving it was issued by a legitimate KMS:

1. **KMS signs** `"dstack-kms-issued:" + appId + appPubkey` — proves the app key was issued by this KMS root
2. **App key signs** `"ethereum:" + derivedPubkeyHex` — proves the derived key belongs to this app
3. **Derived key signs** a message — proves the CVM holds the private key

TEEBridge.sol verifies all three signatures on-chain, recovering the KMS root address and checking it against `allowedKmsRoots`. This is **chain-agnostic** — the contract can live on any EVM chain while accepting proofs from CVMs on any dstack KMS.

### HTTP Proof Pattern

The CVM never needs a wallet or RPC access. Instead:

1. **CVM** runs a Flask server exposing `/proof` with the full DstackProof JSON
2. **External script** (`register.py`) fetches the proof and submits the registration tx
3. **External script** (`onboard.py`) ECIES-encrypts secrets to a member's pubkey and posts on-chain
4. **CVM** decrypts onboarding messages with its KMS-derived key

This eliminates the need for encrypted env delivery (which is broken on some dstack deployments).

## Quick Start

### 1. Deploy the Contract

```bash
# Install foundry deps
forge install foundry-rs/forge-std

# Deploy with KMS root addresses
KMS_ROOTS=0x52d3CF51... forge script script/Deploy.s.sol \
  --broadcast --rpc-url https://mainnet.base.org --private-key $PRIVATE_KEY
```

### 2. Deploy a CVM

**Phala Cloud:**
```bash
phala deploy --name my-bridge \
  --compose docker-compose.yaml \
  --image dstack-0.5.4 --node-id 26 \
  --kms base --private-key $KEY --rpc-url https://mainnet.base.org
```

**Self-hosted dstack** (with serial logging):
```bash
# Use the override file for serial log output + onboarding polling
docker compose -f docker-compose.yaml -f docker-compose.hosted.yaml ...
```

### 3. Register the CVM

```bash
# From HTTP endpoint (if gateway works):
python3 register.py --cvm-url https://APP_ID-8080.gateway.domain \
  --bridge $BRIDGE_CONTRACT --private-key $KEY

# From serial logs (if gateway is broken):
# Find PROOF_JSON=... in serial/container logs, then:
python3 register.py --proof-json '{"code_id":"0x...","dstack_proof":{...}}' \
  --bridge $BRIDGE_CONTRACT --private-key $KEY
```

`register.py` auto-adds the KMS root and code ID to the contract allowlist if needed.

### 4. Send a Secret (Onboarding)

```bash
python3 onboard.py \
  --from-member 0xaaa... --to-member 0xbbb... \
  --secret "shared secret data" \
  --bridge $BRIDGE_CONTRACT --private-key $KEY
```

### 5. Receive Secrets

The CVM decrypts onboarding messages automatically:

- **Polling**: Set `BRIDGE_CONTRACT` env var — the agent polls every 60s and prints `ONBOARDING from=... payload=...`
- **HTTP**: `GET /onboarding?bridge=0x...` returns all decrypted messages as JSON

## API Reference

### `GET /proof`

Returns the full DstackProof needed for on-chain registration.

```json
{
  "code_id": "0x...",
  "dstack_proof": {
    "message_hash": "0x...",
    "message_signature": "0x...",
    "app_signature": "0x...",
    "kms_signature": "0x...",
    "derived_compressed_pubkey": "0x...",
    "app_compressed_pubkey": "0x...",
    "purpose": "ethereum"
  },
  "kms_root": "0x..."
}
```

### `GET /info`

Returns CVM identity info (app ID, member ID, derived address, code ID, KMS root).

### `GET /onboarding?bridge=0x...&rpc=https://...`

Decrypts and returns all onboarding messages for this CVM.

| Param | Required | Default |
|-------|----------|---------|
| `bridge` | yes | — |
| `rpc` | no | `https://mainnet.base.org` |

```json
{
  "member_id": "0x...",
  "messages": [
    {"from": "0x...", "payload": "decrypted secret"}
  ]
}
```

## Reference Deployment

A TEEBridge instance is deployed on **Base mainnet** at [`0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5`](https://basescan.org/address/0x254057d9d92FC7F75E3D49F0c6B0be9eE2A334D5). You should deploy your own for production use.

## Pitfalls & Workarounds

### Encrypted env delivery broken on self-hosted dstack

`vmm-cli.py deploy --env-file` requires the CLI to fetch an encrypt pubkey from KMS. On many self-hosted instances, KMS is firewalled from the internet and the VMM's `kms_url` config is wrong. Use the HTTP Proof Pattern instead — the CVM derives all keys at runtime from the KMS socket.

### Gateway broken on self-hosted dstack

VMM config often has `gateway_urls` pointing to localhost, but the gateway runs in a separate CVM. Deploy without `--gateway` and use `--port tcp:0.0.0.0:HOST_PORT:CVM_PORT` for direct port mapping. Print critical data to serial logs via `tee /dev/ttyS0`.

### Container logs not visible without gateway

`vmm-cli.py logs` only shows the serial console. Use `CMD ["sh", "-c", "python -u agent.py 2>&1 | tee /dev/ttyS0"]` with `privileged: true`. Use the `docker-compose.hosted.yaml` override which sets this up.

### Compose hash churn on Sepolia KMS

Every compose edit needs a new hash whitelisted via `addComposeHash(bytes32)` on the Sepolia DstackApp contract. Get the compose right before deploying. The HTTP Proof Pattern helps — CVM code is stable, external scripts handle changing logic.

### Docker COPY doesn't work in CVMs

Neither Phala CLI nor vmm-cli upload Docker build context. Use `RUN cat > file.py <<'PYEOF' ... PYEOF` in `dockerfile_inline` to inline code.

### `eciespy` not `ecies` on PyPI

The pip package is `eciespy`, but the Python import is `from ecies import ...`.
