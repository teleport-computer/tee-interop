#!/usr/bin/env python3
"""SiLabs edge-node agent: the SiMG301 (secure-boot, ARoT-measured app) runs
on-chain TaskBoard payloads. Its "signature" is a PSA IAT (COSE_Sign1/ES256 by
the SE attestation key) whose nonce = sha256(payload) — attestation IS the
signature. Each fresh token is checked through SilabsVerifier.verify() (view),
i.e. real on-chain RIP-7212 P256, before submit.

  post    -> requester posts payload on TaskBoard addressed to the SiLabs member
  agent   -> watch TaskPosted(assignee=silabs); attest over serial; verify via
             SilabsVerifier view call; submit(id, token) on-chain
  verify  -> off-chain: COSE sig vs se.pem, nonce == sha256(payload), print
             ARoT measurement vs the registered member codeId
"""
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path
from web3 import Web3
from eth_account import Account

HW = Path("/home/amiller/projects/dstack/edge-tee/silabs-secure-vault/hw")
INTEROP = Path("/home/amiller/projects/tee-interop")
SE_PEM = INTEROP / "test/fixtures/silabs/se.pem"
SCRATCH = Path(os.environ.get("SILABS_NODE_TMP", "/tmp/silabs_node"))

BOARD = "0x481D2Cc69d8BaD6B8f41aeC14CA6F324F44c140c"
BRIDGE = "0x31F8e4cf395dcffc6596AE31885FD1E73d6932fa"
VERIFIER = "0x857A6E8810E30e63f5B544180E2F5a139d50351b"
RPC = os.environ.get("RPC_URL", "https://sepolia.base.org")

BOARD_ABI = json.loads("""[
 {"inputs":[{"name":"assignee","type":"bytes32"},{"name":"payload","type":"bytes"}],"name":"post","outputs":[{"name":"id","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"},{"name":"signature","type":"bytes"}],"name":"submit","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"}],"name":"get","outputs":[{"name":"payload","type":"bytes"},{"name":"assignee","type":"bytes32"},{"name":"done","type":"bool"},{"name":"signature","type":"bytes"}],"stateMutability":"view","type":"function"},
 {"inputs":[],"name":"count","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
]""")
VERIFIER_ABI = json.loads("""[
 {"inputs":[{"name":"proof","type":"bytes"}],"name":"verify","outputs":[{"name":"codeId","type":"bytes32"},{"name":"pubkey","type":"bytes"},{"name":"userData","type":"bytes"}],"stateMutability":"view","type":"function"}
]""")
BRIDGE_ABI = json.loads("""[
 {"inputs":[{"name":"memberId","type":"bytes32"}],"name":"getMember","outputs":[{"name":"codeId","type":"bytes32"},{"name":"verifier","type":"address"},{"name":"pubkey","type":"bytes"},{"name":"userData","type":"bytes"},{"name":"registeredAt","type":"uint256"}],"stateMutability":"view","type":"function"}
]""")


def w3():
    return Web3(Web3.HTTPProvider(RPC))


def member_id():
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives import serialization
    pub = load_pem_x509_certificate(SE_PEM.read_bytes()).public_key()
    xy = pub.public_bytes(serialization.Encoding.X962,
                          serialization.PublicFormat.UncompressedPoint)
    return Web3.keccak(xy)


def send(w, fn, *args):
    a = Account.from_key(os.environ["PRIVATE_KEY"])
    tx = fn(*args).build_transaction({
        "from": a.address, "nonce": w.eth.get_transaction_count(a.address),
        "chainId": w.eth.chain_id, "gas": 3_000_000,
        "maxFeePerGas": w.to_wei(0.02, "gwei"), "maxPriorityFeePerGas": w.to_wei(0.01, "gwei")})
    h = w.eth.send_raw_transaction(a.sign_transaction(tx).raw_transaction)
    return w.eth.wait_for_transaction_receipt(h, timeout=180)


def attest(nonce_hex: str) -> bytes:
    tok = subprocess.check_output(
        ["python3", "attest_nonce.py", nonce_hex], cwd=HW).decode().strip()
    return bytes.fromhex(tok)


def board_proof(token: bytes) -> dict:
    SCRATCH.mkdir(exist_ok=True)
    (SCRATCH / "token.hex").write_text(token.hex())
    subprocess.check_call(
        ["python3", "tools/silabs/build_proof.py", "--token", str(SCRATCH / "token.hex"),
         "--out", str(SCRATCH / "proof.json")], cwd=INTEROP, stdout=subprocess.DEVNULL)
    return json.loads((SCRATCH / "proof.json").read_text())


def check_token(token: bytes, payload: bytes):
    """Offline: COSE ES256 sig vs se.pem + nonce == sha256(payload). Raises on failure."""
    import cbor2
    from pycose.messages import Sign1Message
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256
    from cryptography.x509 import load_pem_x509_certificate
    nums = load_pem_x509_certificate(SE_PEM.read_bytes()).public_key().public_numbers()
    msg = Sign1Message.decode(token)
    msg.key = EC2Key(crv=P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
    if not msg.verify_signature():
        raise SystemExit("COSE signature INVALID")
    claims = cbor2.loads(msg.payload)
    if claims[-75008] != hashlib.sha256(payload).digest():
        raise SystemExit("nonce != sha256(payload)")
    comps = {c[1]: c for c in claims[-75006]}
    return comps["ARoT"][2]


def cmd_post(args):
    w = w3()
    board = w.eth.contract(address=BOARD, abi=BOARD_ABI)
    rcpt = send(w, board.functions.post, member_id(), args.payload.encode())
    n = board.functions.count().call()
    print(f"posted task (count now {n}) payload={args.payload!r} tx={rcpt.transactionHash.hex()}")


def cmd_agent(args):
    w = w3()
    board = w.eth.contract(address=BOARD, abi=BOARD_ABI)
    verifier = w.eth.contract(address=VERIFIER, abi=VERIFIER_ABI)
    me = member_id()
    print(f"silabs agent watching TaskBoard {BOARD} for member {me.hex()[:18]}…")
    seen = set()
    while True:
        for i in range(board.functions.count().call()):
            if i in seen:
                continue
            payload, assignee, done, _ = board.functions.get(i).call()
            if assignee != bytes(me) or done:
                seen.add(i); continue
            nonce = hashlib.sha256(payload).hexdigest()
            print(f"task {i}: payload={payload!r}\n  attesting over serial, nonce=sha256(payload)={nonce[:16]}…")
            token = attest(nonce)
            proof = board_proof(token)
            code_id, pubkey, _ = verifier.functions.verify(
                bytes.fromhex(proof["proof"][2:])).call()
            assert Web3.keccak(pubkey) == me
            print(f"  SilabsVerifier.verify (on-chain P256): OK  codeId={code_id.hex()[:16]}… ({proof['measurementName']})")
            rcpt = send(w, board.functions.submit, i, token)
            print(f"  submitted token as result  tx={rcpt.transactionHash.hex()}")
            seen.add(i)
        if args.once:
            break
        time.sleep(args.interval)


def cmd_verify(args):
    w = w3()
    board = w.eth.contract(address=BOARD, abi=BOARD_ABI)
    bridge = w.eth.contract(address=BRIDGE, abi=BRIDGE_ABI)
    payload, assignee, done, token = board.functions.get(args.id).call()
    print(f"task {args.id}: done={done} payload={payload!r}")
    if not done:
        return
    arot = check_token(bytes(token), bytes(payload))
    print(f"  COSE sig valid vs SE cert, nonce == sha256(payload): True")
    print(f"  live ARoT (app measurement) = {arot.hex()}")
    code_id, _, _, _, reg_at = bridge.functions.getMember(assignee).call()
    print(f"  registered member codeId    = {code_id.hex()} (registeredAt={reg_at})")
    print(f"  measurement match: {arot == bytes(code_id)}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("post"); p.add_argument("payload"); p.set_defaults(fn=cmd_post)
    p = sub.add_parser("agent"); p.add_argument("--interval", type=int, default=5); p.add_argument("--once", action="store_true"); p.set_defaults(fn=cmd_agent)
    p = sub.add_parser("verify"); p.add_argument("id", type=int); p.set_defaults(fn=cmd_verify)
    args = ap.parse_args()
    args.fn(args)
