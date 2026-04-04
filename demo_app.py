"""Demo app showing BridgeDstackClient as drop-in for DstackClient."""

import os
from flask import Flask, jsonify
from bridge_client import BridgeDstackClient
from eth_account import Account

app = Flask(__name__)

client = BridgeDstackClient(
    bridge=os.environ['BRIDGE_CONTRACT'],
    verifier=os.environ['VERIFIER_CONTRACT'],
    private_key=os.environ['APP_PRIVATE_KEY'],
)
info = client.info()
print(f"App ID: {info.app_id}")

result = client.get_key("/oracle", "ethereum")
key_hex = result.key
acct = Account.from_key(bytes.fromhex(key_hex.replace('0x', ''))[:32])
print(f"Oracle signer: {acct.address}")

@app.route('/')
def index():
    return jsonify({
        'app_id': info.app_id,
        'oracle_signer': acct.address,
        'key_prefix': key_hex[:18] + '...',
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
