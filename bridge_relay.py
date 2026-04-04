"""TEEBridge relay: always-on service that onboards new members with shared keys."""

import json, os, time, threading
from flask import Flask, jsonify
from dstack_sdk import DstackClient
from eth_account import Account
from eth_keys import keys
from eth_utils import keccak
from eth_abi import encode
from ecies import encrypt as ecies_encrypt
from web3 import Web3


BRIDGE_ABI = json.loads("""[
  {"inputs":[{"name":"verifier","type":"address"},{"name":"proof","type":"bytes"}],"name":"register","outputs":[{"name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"isMember","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getMember","outputs":[{"name":"codeId","type":"bytes32"},{"name":"verifier","type":"address"},{"name":"pubkey","type":"bytes"},{"name":"userData","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"allowedCode","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"addAllowedCode","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"fromMemberId","type":"bytes32"},{"name":"toMemberId","type":"bytes32"},{"name":"encryptedPayload","type":"bytes"}],"name":"onboard","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getOnboarding","outputs":[{"components":[{"name":"fromMember","type":"bytes32"},{"name":"encryptedPayload","type":"bytes"}],"name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"}
]""")

VERIFIER_ABI = json.loads("""[
  {"inputs":[{"name":"root","type":"address"}],"name":"allowedKmsRoots","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"root","type":"address"}],"name":"addKmsRoot","outputs":[],"stateMutability":"nonpayable","type":"function"}
]""")

MEMBER_REGISTERED_TOPIC = '0x' + Web3.keccak(
    text='MemberRegistered(bytes32,bytes32,address,bytes,bytes)').hex()

BRIDGE_CONTRACT = os.environ['BRIDGE_CONTRACT']
VERIFIER_CONTRACT = os.environ['VERIFIER_CONTRACT']
RELAY_PRIVATE_KEY = os.environ['RELAY_PRIVATE_KEY']
RPC_URL = os.environ.get('RPC_URL', 'https://mainnet.base.org')
KEY_PATHS = json.loads(os.environ.get('KEY_PATHS', '["/oracle:ethereum"]'))

w3 = Web3(Web3.HTTPProvider(RPC_URL))
deployer = Account.from_key(RELAY_PRIVATE_KEY)
bridge = w3.eth.contract(address=Web3.to_checksum_address(BRIDGE_CONTRACT), abi=BRIDGE_ABI)
verifier = w3.eth.contract(address=Web3.to_checksum_address(VERIFIER_CONTRACT), abi=VERIFIER_ABI)

nonce_lock = threading.Lock()
_nonce = [None]


def send_tx(fn):
    with nonce_lock:
        _nonce[0] = w3.eth.get_transaction_count(deployer.address)
        tx = fn.build_transaction({
            'from': deployer.address, 'nonce': _nonce[0], 'gas': 500000,
        })
        signed = deployer.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        _nonce[0] += 1
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt['status'] == 1, f"Tx reverted: {tx_hash.hex()}"
    return tx_hash


# === KMS identity (same pattern as bridge_agent.py) ===

client = DstackClient()
info = client.info()
app_id = info.app_id
app_id_bytes20 = bytes.fromhex(app_id.replace('0x', ''))

result = client.get_key("/bridge", "ethereum")
derived_key = bytes.fromhex(result.key.replace('0x', ''))[:32]
priv = keys.PrivateKey(derived_key)
derived_pubkey = priv.public_key.to_compressed_bytes()
acct = Account.from_key(derived_key)

app_sig = bytes.fromhex(result.signature_chain[0].replace('0x', ''))
kms_sig = bytes.fromhex(result.signature_chain[1].replace('0x', ''))

app_msg = f"ethereum:{derived_pubkey.hex()}"
app_msg_hash = keccak(text=app_msg)
app_pubkey = keys.Signature(app_sig).recover_public_key_from_msg_hash(app_msg_hash).to_compressed_bytes()

message_hash = keccak(b"tee-bridge-register")
eth_hash = keccak(b"\x19Ethereum Signed Message:\n32" + message_hash)
message_sig = bytes(acct.unsafe_sign_hash(eth_hash).signature)

code_id = app_id_bytes20 + b'\x00' * 12
member_id = Web3.solidity_keccak(["bytes"], [derived_pubkey])
kms_msg = b"dstack-kms-issued:" + app_id_bytes20 + app_pubkey
kms_msg_hash = keccak(kms_msg)
kms_signer = keys.Signature(kms_sig).recover_public_key_from_msg_hash(kms_msg_hash)

print(f"[relay] app_id={app_id}")
print(f"[relay] member_id=0x{member_id.hex()}")
print(f"[relay] kms_root={kms_signer.to_checksum_address()}")

# === Self-register on TEEBridge ===

kms_root_addr = Web3.to_checksum_address(kms_signer.to_checksum_address())
if not verifier.functions.allowedKmsRoots(kms_root_addr).call():
    print(f"[relay] adding KMS root {kms_root_addr}")
    send_tx(verifier.functions.addKmsRoot(kms_root_addr))

if not bridge.functions.allowedCode(code_id).call():
    print(f"[relay] adding code ID 0x{code_id.hex()}")
    send_tx(bridge.functions.addAllowedCode(code_id))

if not bridge.functions.isMember(member_id).call():
    proof_tuple = (message_hash, message_sig, app_sig, kms_sig,
                   derived_pubkey, app_pubkey, 'ethereum')
    encoded_proof = encode(
        ['bytes32', '(bytes32,bytes,bytes,bytes,bytes,bytes,string)'],
        [code_id, proof_tuple],
    )
    print("[relay] registering on TEEBridge...")
    send_tx(bridge.functions.register(
        Web3.to_checksum_address(VERIFIER_CONTRACT), encoded_proof))
    print("[relay] registered!")
else:
    print("[relay] already registered")

# === Get or generate master key store ===
# If another relay already onboarded us, use those keys.
# Otherwise we're the first relay — generate fresh keys.

key_store = {}
existing_msgs = bridge.functions.getOnboarding(member_id).call()
if existing_msgs:
    from ecies import decrypt as ecies_decrypt
    for msg in existing_msgs:
        plaintext = ecies_decrypt(derived_key, msg[1])
        payload = json.loads(plaintext.decode())
        key_store.update(payload.get('keys', {}))
    print(f"[relay] received {len(key_store)} keys from existing relay")
else:
    for path_purpose in KEY_PATHS:
        parts = path_purpose.rsplit(':', 1)
        path, purpose = parts[0], parts[1] if len(parts) > 1 else ''
        r = client.get_key(path, purpose)
        key_store[path_purpose] = '0x' + r.key.replace('0x', '')
        print(f"[relay] generated key for {path_purpose}")
    print(f"[relay] first relay — generated {len(key_store)} keys")

key_store_json = json.dumps({"keys": key_store})

# === Track who we've onboarded ===

onboarded = {member_id}  # ourselves


def onboard_member(to_member_id, to_pubkey):
    existing = bridge.functions.getOnboarding(to_member_id).call()
    if existing:
        onboarded.add(to_member_id)
        print(f"[relay] 0x{to_member_id.hex()} already has onboarding, skipping")
        return
    encrypted = ecies_encrypt(to_pubkey, key_store_json.encode())
    print(f"[relay] onboarding 0x{to_member_id.hex()} ({len(encrypted)} bytes)")
    send_tx(bridge.functions.onboard(member_id, to_member_id, encrypted))
    onboarded.add(to_member_id)
    print(f"[relay] onboarded 0x{to_member_id.hex()}")


def poll_new_members():
    """Scan for MemberRegistered events and onboard new members."""
    last_block = w3.eth.block_number
    print(f"[relay] polling from block {last_block}")
    while True:
        try:
            current = w3.eth.block_number
            if current > last_block:
                logs = w3.eth.get_logs({
                    'address': Web3.to_checksum_address(BRIDGE_CONTRACT),
                    'fromBlock': last_block + 1,
                    'toBlock': current,
                    'topics': [MEMBER_REGISTERED_TOPIC],
                })
                for log in logs:
                    new_member_id = log['topics'][1]
                    if new_member_id in onboarded:
                        continue
                    member_info = bridge.functions.getMember(new_member_id).call()
                    pubkey = member_info[2]
                    onboard_member(new_member_id, pubkey)
                last_block = current
        except Exception as e:
            print(f"[relay] poll error: {e}")
        time.sleep(10)


# === Also check for any existing unboarded members (catch up) ===

def catch_up():
    """Check recent history for members we haven't onboarded."""
    current = w3.eth.block_number
    lookback = min(10000, current)
    logs = w3.eth.get_logs({
        'address': Web3.to_checksum_address(BRIDGE_CONTRACT),
        'fromBlock': current - lookback,
        'toBlock': current,
        'topics': [MEMBER_REGISTERED_TOPIC],
    })
    for log in logs:
        mid = log['topics'][1]
        if mid in onboarded:
            continue
        try:
            existing_onboarding = bridge.functions.getOnboarding(mid).call()
            already_has = any(msg[0] == member_id for msg in existing_onboarding)
            if already_has:
                onboarded.add(mid)
                continue
            member_info = bridge.functions.getMember(mid).call()
            onboard_member(mid, member_info[2])
        except Exception as e:
            print(f"[relay] catch_up error for {mid.hex()}: {e}")
        time.sleep(1)


print("[relay] catching up on existing members...")
catch_up()

# === HTTP status endpoint ===

app = Flask(__name__)

@app.route('/status')
def status():
    return jsonify({
        'relay_member_id': '0x' + member_id.hex(),
        'app_id': app_id,
        'keys': list(key_store.keys()),
        'onboarded_count': len(onboarded) - 1,
        'bridge': BRIDGE_CONTRACT,
    })

@app.route('/proof')
def proof():
    return jsonify({
        'code_id': '0x' + code_id.hex(),
        'kms_root': kms_signer.to_checksum_address(),
        'member_id': '0x' + member_id.hex(),
        'app_id': app_id,
    })


if __name__ == '__main__':
    threading.Thread(target=poll_new_members, daemon=True).start()
    print("[relay] ready, polling for new members")
    app.run(host='0.0.0.0', port=8080)
