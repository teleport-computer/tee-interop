#!/usr/bin/env python3
"""Register a CVM on the TEEBridge contract using its /proof endpoint."""

import argparse, json, requests
from web3 import Web3
from eth_account import Account

BRIDGE_ABI = json.loads("""[
  {"inputs":[{"name":"codeId","type":"bytes32"},{"components":[{"name":"messageHash","type":"bytes32"},{"name":"messageSignature","type":"bytes"},{"name":"appSignature","type":"bytes"},{"name":"kmsSignature","type":"bytes"},{"name":"derivedCompressedPubkey","type":"bytes"},{"name":"appCompressedPubkey","type":"bytes"},{"name":"purpose","type":"string"}],"name":"dstackProof","type":"tuple"}],"name":"registerDstack","outputs":[{"name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"isMember","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"allowedCode","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"addAllowedCode","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"root","type":"address"}],"name":"allowedKmsRoots","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"root","type":"address"}],"name":"addKmsRoot","outputs":[],"stateMutability":"nonpayable","type":"function"}
]""")

parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('--cvm-url', help='CVM base URL (e.g. http://host:port)')
group.add_argument('--proof-json', help='Proof JSON string (from serial logs PROOF_JSON=...)')
parser.add_argument('--bridge', required=True, help='TEEBridge contract address')
parser.add_argument('--private-key', required=True, help='Deployer private key')
parser.add_argument('--rpc-url', default='https://mainnet.base.org')
args = parser.parse_args()

if args.cvm_url:
    print(f"Fetching proof from {args.cvm_url}/proof ...")
    proof_data = requests.get(f"{args.cvm_url}/proof").json()
else:
    proof_data = json.loads(args.proof_json)
p = proof_data['dstack_proof']
code_id = bytes.fromhex(proof_data['code_id'].replace('0x', ''))
kms_root = proof_data['kms_root']

dstack_proof = (
    bytes.fromhex(p['message_hash'][2:]),
    bytes.fromhex(p['message_signature'][2:]),
    bytes.fromhex(p['app_signature'][2:]),
    bytes.fromhex(p['kms_signature'][2:]),
    bytes.fromhex(p['derived_compressed_pubkey'][2:]),
    bytes.fromhex(p['app_compressed_pubkey'][2:]),
    p['purpose'],
)

member_id = Web3.solidity_keccak(["bytes"], [bytes.fromhex(p['derived_compressed_pubkey'][2:])])
print(f"Code ID: {proof_data['code_id']}")
print(f"Member ID: 0x{member_id.hex()}")
print(f"KMS root: {kms_root}")

w3 = Web3(Web3.HTTPProvider(args.rpc_url))
deployer = Account.from_key(args.private_key)
bridge = w3.eth.contract(address=Web3.to_checksum_address(args.bridge), abi=BRIDGE_ABI)

def send_tx(fn):
    tx = fn.build_transaction({
        'from': deployer.address,
        'nonce': w3.eth.get_transaction_count(deployer.address),
        'gas': 500000,
    })
    signed = deployer.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    assert receipt['status'] == 1, f"Tx reverted: {tx_hash.hex()}"
    return tx_hash

# Check KMS root
if not bridge.functions.allowedKmsRoots(Web3.to_checksum_address(kms_root)).call():
    print(f"Adding KMS root {kms_root} ...")
    tx_hash = send_tx(bridge.functions.addKmsRoot(Web3.to_checksum_address(kms_root)))
    print(f"  tx: {tx_hash.hex()}")

# Check code allowlist
if not bridge.functions.allowedCode(code_id).call():
    print(f"Adding allowed code {proof_data['code_id']} ...")
    tx_hash = send_tx(bridge.functions.addAllowedCode(code_id))
    print(f"  tx: {tx_hash.hex()}")

# Register
if bridge.functions.isMember(member_id).call():
    print("Already registered!")
else:
    print("Registering ...")
    tx_hash = send_tx(bridge.functions.registerDstack(code_id, dstack_proof))
    print(f"Registered! tx: {tx_hash.hex()}")
