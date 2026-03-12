#!/usr/bin/env python3
"""Send an onboarding secret to a TEEBridge member via ECIES encryption."""

import argparse, json
from web3 import Web3
from eth_account import Account
from ecies import encrypt as ecies_encrypt

BRIDGE_ABI = json.loads("""[
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getMember","outputs":[{"name":"codeId","type":"bytes32"},{"name":"pubkey","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"isMember","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"fromMemberId","type":"bytes32"},{"name":"toMemberId","type":"bytes32"},{"name":"encryptedPayload","type":"bytes"}],"name":"onboard","outputs":[],"stateMutability":"nonpayable","type":"function"}
]""")

parser = argparse.ArgumentParser()
parser.add_argument('--from-member', required=True, help='Sender member ID (hex)')
parser.add_argument('--to-member', required=True, help='Recipient member ID (hex)')
parser.add_argument('--secret', required=True, help='Plaintext secret to send')
parser.add_argument('--bridge', required=True, help='TEEBridge contract address')
parser.add_argument('--private-key', required=True, help='Deployer private key')
parser.add_argument('--rpc-url', default='https://mainnet.base.org')
args = parser.parse_args()

w3 = Web3(Web3.HTTPProvider(args.rpc_url))
deployer = Account.from_key(args.private_key)
bridge = w3.eth.contract(address=Web3.to_checksum_address(args.bridge), abi=BRIDGE_ABI)

from_id = bytes.fromhex(args.from_member.replace('0x', ''))
to_id = bytes.fromhex(args.to_member.replace('0x', ''))

assert bridge.functions.isMember(from_id).call(), f"Sender {args.from_member} not registered"
assert bridge.functions.isMember(to_id).call(), f"Recipient {args.to_member} not registered"

peer_info = bridge.functions.getMember(to_id).call()
peer_pubkey = peer_info[1]
print(f"Recipient pubkey: {peer_pubkey.hex()}")

encrypted = ecies_encrypt(peer_pubkey, args.secret.encode())
print(f"Encrypted payload: {len(encrypted)} bytes")

tx = bridge.functions.onboard(from_id, to_id, encrypted).build_transaction({
    'from': deployer.address,
    'nonce': w3.eth.get_transaction_count(deployer.address),
    'gas': 500000,
})
signed = deployer.sign_transaction(tx)
tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
assert receipt['status'] == 1, f"Onboard reverted: {tx_hash.hex()}"
print(f"Onboarded! tx: {tx_hash.hex()}")
