#!/usr/bin/env python3
"""Edge-node agent: an attested Pixel that runs on-chain TaskBoard payloads.

Loop:
  provision  -> phone mints a persistent StrongBox key, attested; register it
                as a bridge member on the (testnet) AndroidKeyAttestationVerifier.
  post       -> requester posts a payload on TaskBoard addressed to the member.
  agent      -> watch TaskBoard for TaskPosted(assignee=me); for each, ask the
                phone to ECDSA-P256 sign the payload with its StrongBox node key,
                then submit(id, signature) on-chain.
  verify     -> off-chain, check the on-chain signature against the member pubkey.

Trust it earns: "a genuine, unique attested device produced this signature"
(Stage-0 / sybil-resistant). NOT "the correct code ran" — key use is gated by
app identity, not code. See docs/android/README.md.

Phone must be reachable:  adb forward tcp:7340 localabstract:edgetee
"""
import argparse, json, os, subprocess, sys, time, urllib.request
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_abi import encode as abi_encode
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
STATE = HERE / "node_state.json"
PHONE = "http://localhost:7340"
PY = "/home/amiller/projects/dstack/edge-tee/rt1180-se051/firmware/.venv/bin/python"
BUILD_PROOF = REPO / "tools/android_keyattest/build_proof.py"
NODE_PEM = "/home/amiller/projects/dstack/edge-tee/pixel-attest/pixel_node.pem"

RPC = os.environ.get("RPC_URL", "https://sepolia.base.org")

BRIDGE_ABI = json.loads("""[
 {"inputs":[{"name":"verifier","type":"address"},{"name":"proof","type":"bytes"}],"name":"register","outputs":[{"name":"","type":"bytes32"}],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"addAllowedCode","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"codeId","type":"bytes32"}],"name":"allowedCode","outputs":[{"name":"","type":"bool"}],"stateMutability":"view","type":"function"},
 {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getMember","outputs":[{"name":"codeId","type":"bytes32"},{"name":"verifier","type":"address"},{"name":"pubkey","type":"bytes"},{"name":"userData","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view","type":"function"}
]""")
VERIFIER_ABI = json.loads("""[
 {"inputs":[{"name":"proof","type":"bytes"}],"name":"verify","outputs":[{"name":"codeId","type":"bytes32"},{"name":"pubkey","type":"bytes"},{"name":"userData","type":"bytes"}],"stateMutability":"view","type":"function"}
]""")
BOARD_ABI = json.loads("""[
 {"inputs":[{"name":"assignee","type":"bytes32"},{"name":"payload","type":"bytes"}],"name":"post","outputs":[{"name":"id","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"},{"name":"signature","type":"bytes"}],"name":"submit","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"}],"name":"get","outputs":[{"name":"payload","type":"bytes"},{"name":"assignee","type":"bytes32"},{"name":"done","type":"bool"},{"name":"signature","type":"bytes"}],"stateMutability":"view","type":"function"},
 {"inputs":[],"name":"count","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"},
 {"anonymous":false,"inputs":[{"indexed":true,"name":"id","type":"uint256"},{"indexed":true,"name":"assignee","type":"bytes32"},{"indexed":false,"name":"payload","type":"bytes"}],"name":"TaskPosted","type":"event"}
]""")


def w3():
    return Web3(Web3.HTTPProvider(RPC))


def acct():
    return Account.from_key(os.environ["PRIVATE_KEY"])


def phone_post(path, obj):
    req = urllib.request.Request(PHONE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def load_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(s):
    STATE.write_text(json.dumps(s, indent=2))


def send(w, fn, *args):
    a = acct()
    tx = fn(*args).build_transaction({
        "from": a.address, "nonce": w.eth.get_transaction_count(a.address),
        "chainId": w.eth.chain_id, "gas": 3_000_000,
        "maxFeePerGas": w.to_wei(0.02, "gwei"), "maxPriorityFeePerGas": w.to_wei(0.01, "gwei")})
    signed = a.sign_transaction(tx)
    h = w.eth.send_raw_transaction(signed.raw_transaction)
    rcpt = w.eth.wait_for_transaction_receipt(h, timeout=180)
    return rcpt


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_provision(args):
    w = w3()
    s = load_state()
    d = phone_post("/provision", {})
    Path(NODE_PEM).write_text(d["chain"].encode().decode("unicode_escape"))
    print(f"provisioned node key (alias={d['alias']}) challenge={d['challenge_hex'][:20]}…")

    proof = subprocess.check_output(
        [PY, str(BUILD_PROOF), NODE_PEM, "0x" + d["challenge_hex"]], cwd=REPO).decode().strip()
    proof_bytes = bytes.fromhex(proof[2:])

    verifier = w.eth.contract(address=Web3.to_checksum_address(args.verifier), abi=VERIFIER_ABI)
    code_id, pubkey, _ = verifier.functions.verify(proof_bytes).call()
    print(f"codeId={code_id.hex()}  member pubkey={pubkey.hex()[:24]}…")

    bridge = w.eth.contract(address=Web3.to_checksum_address(args.bridge), abi=BRIDGE_ABI)
    if not bridge.functions.allowedCode(code_id).call():
        print("addAllowedCode…", send(w, bridge.functions.addAllowedCode, code_id).transactionHash.hex())
    rcpt = send(w, bridge.functions.register, Web3.to_checksum_address(args.verifier), proof_bytes)
    member_id = Web3.keccak(pubkey)
    print(f"registered member {member_id.hex()}  tx={rcpt.transactionHash.hex()}")

    s.update({"bridge": args.bridge, "verifier": args.verifier, "board": args.board,
              "member_id": member_id.hex(), "pubkey_spki": pubkey.hex()})
    save_state(s)


def cmd_post(args):
    w = w3(); s = load_state()
    board = w.eth.contract(address=Web3.to_checksum_address(s["board"]), abi=BOARD_ABI)
    member = bytes.fromhex(s["member_id"].replace("0x", ""))
    payload = args.payload.encode()
    rcpt = send(w, board.functions.post, member, payload)
    log = board.events.TaskPosted().process_receipt(rcpt)[0]
    print(f"posted task id={log['args']['id']} payload={args.payload!r} tx={rcpt.transactionHash.hex()}")


def _verify_sig(pubkey_spki: bytes, payload: bytes, sig_der: bytes) -> bool:
    pub = serialization.load_der_public_key(pubkey_spki)
    try:
        pub.verify(sig_der, payload, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def cmd_agent(args):
    w = w3(); s = load_state()
    board = w.eth.contract(address=Web3.to_checksum_address(s["board"]), abi=BOARD_ABI)
    member = bytes.fromhex(s["member_id"].replace("0x", ""))
    pubkey = bytes.fromhex(s["pubkey_spki"].replace("0x", ""))
    print(f"agent watching TaskBoard {s['board']} for member {s['member_id'][:18]}…")
    seen = set()
    while True:
        n = board.functions.count().call()
        for i in range(n):
            if i in seen:
                continue
            payload, assignee, done, _ = board.functions.get(i).call()
            if assignee != member or done:
                seen.add(i); continue
            print(f"task {i}: payload={payload!r} → asking phone to StrongBox-sign")
            r = phone_post("/sign", {"message_hex": "0x" + payload.hex()})
            sig = bytes.fromhex(r["signature_der_hex"])
            ok = _verify_sig(pubkey, payload, sig)
            print(f"  sig verifies vs member pubkey: {ok}")
            rcpt = send(w, board.functions.submit, i, sig)
            print(f"  submitted result tx={rcpt.transactionHash.hex()}")
            seen.add(i)
        if args.once:
            break
        time.sleep(args.interval)


def cmd_verify(args):
    w = w3(); s = load_state()
    board = w.eth.contract(address=Web3.to_checksum_address(s["board"]), abi=BOARD_ABI)
    pubkey = bytes.fromhex(s["pubkey_spki"].replace("0x", ""))
    payload, assignee, done, sig = board.functions.get(args.id).call()
    print(f"task {args.id}: done={done} payload={payload!r}")
    if done:
        print(f"  signature verifies vs attested member pubkey: {_verify_sig(pubkey, payload, sig)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provision"); p.add_argument("--bridge", required=True); p.add_argument("--verifier", required=True); p.add_argument("--board", required=True); p.set_defaults(fn=cmd_provision)
    p = sub.add_parser("post"); p.add_argument("payload"); p.set_defaults(fn=cmd_post)
    p = sub.add_parser("agent"); p.add_argument("--interval", type=int, default=5); p.add_argument("--once", action="store_true"); p.set_defaults(fn=cmd_agent)
    p = sub.add_parser("verify"); p.add_argument("id", type=int); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    args.fn(args)
