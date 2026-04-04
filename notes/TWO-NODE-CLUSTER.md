# Launching a 2-Node Cluster on prod5 + prod9

Two CVMs sharing the same `app_id` on different physical machines, deriving identical keys from Base KMS.

## Prerequisites

- `phala` CLI installed and logged in (`phala login`)
- A funded Base wallet (`PRIVATE_KEY` env var)
- A `docker-compose.yaml` for your app

## Quick Summary

1. Deploy on prod5 with `phala deploy --node-id 26`
2. Add prod9's device to the AppAuth contract
3. Create a replica on prod9 via `POST /cvms/{uuid}/replicas`
4. Both instances share the same `app_id` and derive the same keys

## Step-by-Step

### 1. Deploy the first node on prod5

```bash
export PRIVATE_KEY=0x...  # funded Base wallet

phala deploy -n my-app \
  -c docker-compose.yaml \
  --kms base \
  --private-key $PRIVATE_KEY \
  --node-id 26
```

This creates an AppAuth contract on Base with:
- Your compose hash registered
- prod5's device ID registered
- Your wallet as owner

Save the `app_id` and `vm_uuid` from the output.

### 2. Wait for it to be running

```bash
# Poll until running
phala cvms get my-app --json | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['status'])"
```

### 3. Add prod9's device to the AppAuth contract

The AppAuth contract (address = `0x<app_id>` with checksum) needs prod9's device ID added.

prod9's device ID: `573f4908a95b4159c4c262fc8244a485a77d874dc4b1bdf28d38afe80ca77431`

```python
from web3 import Web3
from eth_account import Account

w3 = Web3(Web3.HTTPProvider('https://mainnet.base.org'))
acct = Account.from_key(PRIVATE_KEY)

app_auth = Web3.to_checksum_address('0x<YOUR_APP_ID>')
ABI = [{"inputs":[{"name":"deviceId","type":"bytes32"}],"name":"addDevice","outputs":[],"stateMutability":"nonpayable","type":"function"}]

c = w3.eth.contract(address=app_auth, abi=ABI)
prod9_device = bytes.fromhex('573f4908a95b4159c4c262fc8244a485a77d874dc4b1bdf28d38afe80ca77431')

tx = c.functions.addDevice(prod9_device).build_transaction({
    'from': acct.address,
    'nonce': w3.eth.get_transaction_count(acct.address),
    'gas': 100000,
})
signed = acct.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
assert receipt.status == 1
```

### 4. Create a replica on prod9

The `phala cvms replicate` CLI has bugs. Use the REST API directly:

```python
import requests, json
from pathlib import Path

# Load API key from phala CLI credentials
creds = json.loads((Path.home() / ".phala-cloud" / "credentials.json").read_text())
API_KEY = creds['profiles'][creds['current_profile']]['token']

resp = requests.post(
    f"https://cloud-api.phala.network/api/v1/cvms/<VM_UUID>/replicas",
    headers={"X-API-Key": API_KEY, "Content-Type": "application/json"},
    json={"teepod_id": 18}  # prod9
)
resp.raise_for_status()
print(resp.json())
```

**Important:** Use the `vm_uuid` (not `app_id`) in the URL. Using `app_id` returns "Multiple CVMs match" once replicas exist.

### 5. Verify

Both instances share the same `app_id` and derive identical keys:

```bash
# By app_id (load-balanced across replicas on that gateway)
curl https://<app_id>-8080.dstack-base-prod5.phala.network/
curl https://<app_id>-8080.dstack-base-prod9.phala.network/

# By instance_id (target specific replica)
curl https://<instance_id>-8080.dstack-base-prod5.phala.network/
curl https://<instance_id>-8080.dstack-base-prod9.phala.network/
```

Get instance IDs with `phala cvms get <name> --json` → `.instance_id` field.

## URL Scheme

- `https://<app_id>-<port>.<gateway>/` — routes to whichever replica is on that gateway's node
- `https://<instance_id>-<port>.<gateway>/` — routes to a specific replica

## Device IDs

These are the device IDs for per-device allowlisting on the AppAuth contract:

| Node | ID | Device ID |
|------|----|-----------|
| prod5 | 26 | `c4691f9c88f44e05cbc45521678e72b99fcd54fa35d302f13e8f9fa9727f33a6` |
| prod9 | 18 | `573f4908a95b4159c4c262fc8244a485a77d874dc4b1bdf28d38afe80ca77431` |

**Do not use prod7** (id=12) — it has a device ID mismatch between what `phala deploy` registers and what the KMS checks at boot time. See KMS-AGGREGATOR.md for details.

## Known Issues

1. **`phala cvms replicate` CLI is broken for Base KMS** — returns validation errors or "not found". Use the REST API directly.

2. **prod7 device ID mismatch** — per-device allowlisting fails. The CVM info API, list-nodes API, and KMS each report different device IDs for prod7.

3. **Replica naming** — replicas get auto-generated names like `my-app-rep-56z97`. You can't control the name.

## Verified Results

Three replicas of `1b245cae7484c54904d73fe006522107061c60d8`:

| Name | Node | Instance ID |
|------|------|-------------|
| replica-test | prod5 | `38cf8bee3c03a7ab6cf169a1cc9453fac92ada47` |
| replica-test-rep-56z97 | prod9 | `7a6569f18e83cfaf57bd359e90531d224de993aa` |
| replica-test-rep-aok6b | prod9 | `9e543e13058c1e89a984c7b672cc504a5cfdd29e` |

All three return `derived_address: 0x901052E4337659aE02e11B24d4aF8F9462088fE7` — same key.
