"""Drop-in replacement for DstackClient that receives keys via TEEBridge onboarding."""

import json, time
from dataclasses import dataclass
from typing import List
from dstack_sdk import DstackClient
from eth_account import Account
from eth_keys import keys
from eth_utils import keccak
from eth_abi import encode
from ecies import decrypt as ecies_decrypt
from web3 import Web3


BRIDGE_ABI = json.loads("""[
  {"inputs":[{"name":"verifier","type":"address"},{"name":"proof","type":"bytes"}],"name":"register","outputs":[{"name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"isMember","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"allowedCode","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"addAllowedCode","outputs":[],"stateMutability":"nonpayable","type":"function"},
  {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getOnboarding","outputs":[{"components":[{"name":"fromMember","type":"bytes32"},{"name":"encryptedPayload","type":"bytes"}],"name":"","type":"tuple[]"}],"stateMutability":"view","type":"function"}
]""")

VERIFIER_ABI = json.loads("""[
  {"inputs":[{"name":"root","type":"address"}],"name":"allowedKmsRoots","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
  {"inputs":[{"name":"root","type":"address"}],"name":"addKmsRoot","outputs":[],"stateMutability":"nonpayable","type":"function"}
]""")


@dataclass
class BridgeKeyResponse:
    """Mimics dstack_sdk GetKeyResponse."""
    key: str
    signature_chain: List[str]

    def decode_key(self):
        return bytes.fromhex(self.key.replace('0x', ''))

    def decode_signature_chain(self):
        return [bytes.fromhex(s.replace('0x', '')) for s in self.signature_chain]


class BridgeDstackClient:
    """Drop-in for DstackClient. Gets keys from TEEBridge relay instead of per-app KMS derivation."""

    def __init__(self, bridge, verifier, private_key, rpc_url='https://mainnet.base.org'):
        self._bridge_addr = bridge
        self._verifier_addr = verifier
        self._rpc_url = rpc_url
        self._w3 = Web3(Web3.HTTPProvider(rpc_url))
        self._deployer = Account.from_key(private_key)
        self._nonce = None
        self._keys = {}
        self._registered = False
        self._onboarded = False

        self._real = DstackClient()
        self._bridge = self._w3.eth.contract(
            address=Web3.to_checksum_address(bridge), abi=BRIDGE_ABI)
        self._verifier = self._w3.eth.contract(
            address=Web3.to_checksum_address(verifier), abi=VERIFIER_ABI)

        self._derive_identity()

    def _derive_identity(self):
        """Derive key + build proof from real KMS, exactly like bridge_agent.py."""
        info = self._real.info()
        self._app_id = info.app_id
        app_id_bytes20 = bytes.fromhex(self._app_id.replace('0x', ''))

        result = self._real.get_key("/bridge", "ethereum")
        self._derived_key = bytes.fromhex(result.key.replace('0x', ''))[:32]
        priv = keys.PrivateKey(self._derived_key)
        self._derived_pubkey = priv.public_key.to_compressed_bytes()
        acct = Account.from_key(self._derived_key)

        app_sig = bytes.fromhex(result.signature_chain[0].replace('0x', ''))
        kms_sig = bytes.fromhex(result.signature_chain[1].replace('0x', ''))

        app_msg = f"ethereum:{self._derived_pubkey.hex()}"
        app_msg_hash = keccak(text=app_msg)
        app_pubkey = keys.Signature(app_sig).recover_public_key_from_msg_hash(app_msg_hash).to_compressed_bytes()

        message_hash = keccak(b"tee-bridge-register")
        eth_hash = keccak(b"\x19Ethereum Signed Message:\n32" + message_hash)
        message_sig = bytes(acct.unsafe_sign_hash(eth_hash).signature)

        code_id = app_id_bytes20 + b'\x00' * 12
        kms_msg = b"dstack-kms-issued:" + app_id_bytes20 + app_pubkey
        kms_msg_hash = keccak(kms_msg)
        kms_signer = keys.Signature(kms_sig).recover_public_key_from_msg_hash(kms_msg_hash)

        self._code_id = code_id
        self._member_id = Web3.solidity_keccak(["bytes"], [self._derived_pubkey])
        self._kms_root = kms_signer.to_checksum_address()
        self._proof_tuple = (
            message_hash, message_sig, app_sig, kms_sig,
            self._derived_pubkey, app_pubkey, 'ethereum',
        )
        print(f"[bridge] app_id={self._app_id} member_id=0x{self._member_id.hex()}")

    def _send_tx(self, fn):
        if self._nonce is None:
            self._nonce = self._w3.eth.get_transaction_count(self._deployer.address)
        tx = fn.build_transaction({
            'from': self._deployer.address,
            'nonce': self._nonce,
            'gas': 500000,
        })
        signed = self._deployer.sign_transaction(tx)
        tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
        self._nonce += 1
        receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash)
        assert receipt['status'] == 1, f"Tx reverted: {tx_hash.hex()}"
        print(f"[bridge] tx: {tx_hash.hex()}")
        return tx_hash

    def _register(self):
        if self._registered:
            return
        if self._bridge.functions.isMember(self._member_id).call():
            print("[bridge] already registered")
            self._registered = True
            return

        if not self._verifier.functions.allowedKmsRoots(
                Web3.to_checksum_address(self._kms_root)).call():
            print(f"[bridge] adding KMS root {self._kms_root}")
            self._send_tx(self._verifier.functions.addKmsRoot(
                Web3.to_checksum_address(self._kms_root)))

        if not self._bridge.functions.allowedCode(self._code_id).call():
            print(f"[bridge] adding code ID 0x{self._code_id.hex()}")
            self._send_tx(self._bridge.functions.addAllowedCode(self._code_id))

        encoded_proof = encode(
            ['bytes32', '(bytes32,bytes,bytes,bytes,bytes,bytes,string)'],
            [self._code_id, self._proof_tuple],
        )
        print("[bridge] registering on TEEBridge...")
        self._send_tx(self._bridge.functions.register(
            Web3.to_checksum_address(self._verifier_addr), encoded_proof))
        self._registered = True

    def _poll_onboarding(self, timeout=120):
        if self._onboarded:
            return
        print("[bridge] waiting for relay to onboard keys...")
        start = time.time()
        while time.time() - start < timeout:
            msgs = self._bridge.functions.getOnboarding(self._member_id).call()
            if msgs:
                for msg in msgs:
                    plaintext = ecies_decrypt(self._derived_key, msg[1])
                    payload = json.loads(plaintext.decode())
                    self._keys.update(payload.get('keys', {}))
                print(f"[bridge] received {len(self._keys)} keys from relay")
                self._onboarded = True
                return
            time.sleep(3)
        raise TimeoutError("[bridge] relay did not onboard keys within timeout")

    def info(self):
        return self._real.info()

    def get_key(self, path, purpose=""):
        cache_key = f"{path}:{purpose}"
        if cache_key not in self._keys:
            self._register()
            self._poll_onboarding()
        if cache_key not in self._keys:
            raise KeyError(f"[bridge] relay did not provide key for {cache_key}")
        return BridgeKeyResponse(key=self._keys[cache_key], signature_chain=[])
