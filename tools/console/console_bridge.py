#!/usr/bin/env python3
"""Operator-console bridge for the tech demo (two devices, two vendors).

Serves docs/console/ on http://127.0.0.1:8190 and drives both attested nodes:
  Pixel 6a (Titan M2 StrongBox, X.509 key attestation)  via adb tcp:8151
  SiMG301 (Secure Vault SE, COSE_Sign1 PSA IAT)         via /dev/ttyACM0

Endpoints: /api/info, /api/pixel/attest, /api/silabs/attest,
/api/task/post {device,payload}, /api/task/list, /api/task/run {id},
/api/task/verify {id}. Txs are signed with PRIVATE_KEY from the environment
(the "small local signer" the page calls).
"""
import hashlib, json, os, secrets, subprocess, sys, tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.request import Request, urlopen

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools/android_keyattest"))
from build_proof import build_proof, load_chain, parse_leaf_extension

from web3 import Web3
from eth_account import Account

HW = Path("/home/amiller/projects/dstack/edge-tee/silabs-secure-vault/hw")
INTEROP = Path("/home/amiller/projects/tee-interop")
SE_PEM = INTEROP / "test/fixtures/silabs/se.pem"
PAGE_DIR = REPO / "docs" / "console"
PHONE = "http://127.0.0.1:8151"
SCRATCH = Path(tempfile.gettempdir()) / "console_bridge"

BOARD = "0x481D2Cc69d8BaD6B8f41aeC14CA6F324F44c140c"
RPC = os.environ.get("RPC_URL", "https://sepolia.base.org")
BOARD_ABI = json.loads("""[
 {"inputs":[{"name":"assignee","type":"bytes32"},{"name":"payload","type":"bytes"}],"name":"post","outputs":[{"name":"id","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"},{"name":"signature","type":"bytes"}],"name":"submit","outputs":[],"stateMutability":"nonpayable","type":"function"},
 {"inputs":[{"name":"id","type":"uint256"}],"name":"get","outputs":[{"name":"payload","type":"bytes"},{"name":"assignee","type":"bytes32"},{"name":"done","type":"bool"},{"name":"signature","type":"bytes"}],"stateMutability":"view","type":"function"},
 {"inputs":[],"name":"count","outputs":[{"name":"","type":"uint256"}],"stateMutability":"view","type":"function"}
]""")

w3 = Web3(Web3.HTTPProvider(RPC))
board = w3.eth.contract(address=BOARD, abi=BOARD_ABI)

PIXEL_SPKI = bytes.fromhex(json.loads((REPO / "node/node_state.json").read_text())["pubkey_spki"])
PIXEL_MEMBER = Web3.keccak(PIXEL_SPKI)


def se_xy():
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives import serialization
    pub = load_pem_x509_certificate(SE_PEM.read_bytes()).public_key()
    return pub.public_bytes(serialization.Encoding.X962,
                            serialization.PublicFormat.UncompressedPoint)


SILABS_MEMBER = Web3.keccak(se_xy())
NAMES = {PIXEL_MEMBER: "pixel", SILABS_MEMBER: "silabs"}


def phone(path, body=None):
    req = Request(PHONE + path, data=json.dumps(body).encode() if body is not None else None,
                  method="POST" if body is not None else "GET")
    with urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def send_tx(fn, *args):
    a = Account.from_key(os.environ["PRIVATE_KEY"])
    tx = fn(*args).build_transaction({
        "from": a.address, "nonce": w3.eth.get_transaction_count(a.address),
        "chainId": w3.eth.chain_id, "gas": 3_000_000,
        "maxFeePerGas": w3.to_wei(0.02, "gwei"), "maxPriorityFeePerGas": w3.to_wei(0.01, "gwei")})
    h = w3.eth.send_raw_transaction(a.sign_transaction(tx).raw_transaction)
    return w3.eth.wait_for_transaction_receipt(h, timeout=180)


# ── pixel: X.509 attestation, decoded ─────────────────────────────────────────

VB_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}
SEC_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}


def pixel_attest():
    nonce = secrets.token_hex(16)
    r = phone("/attest", {"challenge": nonce})
    cert_challenge = hashlib.sha256(nonce.encode() + bytes.fromhex(r["apk_hash"])).digest()
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(r["chain"].encode().decode("unicode_escape"))
        pem_path = Path(f.name)
    try:
        chain = load_chain(pem_path)
        ext = parse_leaf_extension(chain[0])
        proof = "0x" + build_proof(pem_path, cert_challenge).hex()
    finally:
        os.unlink(pem_path)
    certs = [{"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
              "sigAlg": c.signature_algorithm_oid._name} for c in chain]
    return {
        "nonce": nonce, "apk_hash": r["apk_hash"],
        "cert_challenge": cert_challenge.hex(),
        "pem": r["chain"].encode().decode("unicode_escape"),
        "chain": certs,
        "ext": {
            "challenge": ext["challenge"].hex(),
            "attestSecLevel": SEC_LEVEL.get(ext["attestSecLevel"], str(ext["attestSecLevel"])),
            "keyMintSecLevel": SEC_LEVEL.get(ext["keyMintSecLevel"], str(ext["keyMintSecLevel"])),
            "verifiedBootState": VB_STATE.get(ext["verifiedBootState"], str(ext["verifiedBootState"])),
            "deviceLocked": ext["deviceLocked"],
            "verifiedBootHash": ext["verifiedBootHash"].hex(),
            "osPatchLevel": ext["osPatchLevel"],
            "appCertSha256": ext["appCertSha256"].hex(),
        },
        "proof": proof,
    }


# ── silabs: COSE_Sign1 PSA IAT, decoded ───────────────────────────────────────

CLAIM_NAMES = {-75000: "profile", -75001: "client-id", -75002: "security-lifecycle",
               -75003: "implementation-id", -75004: "boot-seed",
               -75006: "software-components", -75008: "nonce", -75009: "instance-id (UEID)"}


def silabs_attest(nonce: bytes):
    import cbor2
    from pycose.messages import Sign1Message
    from pycose.keys import EC2Key
    from pycose.keys.curves import P256
    from cryptography.x509 import load_pem_x509_certificate
    tok = subprocess.check_output(["python3", "attest_nonce.py", nonce.hex()], cwd=HW).decode().strip()
    token = bytes.fromhex(tok)

    nums = load_pem_x509_certificate(SE_PEM.read_bytes()).public_key().public_numbers()
    msg = Sign1Message.decode(token)
    msg.key = EC2Key(crv=P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
    if not msg.verify_signature():
        raise RuntimeError("COSE signature invalid vs SE cert")
    claims = cbor2.loads(msg.payload)

    SCRATCH.mkdir(exist_ok=True)
    (SCRATCH / "token.hex").write_text(token.hex())
    subprocess.check_call(["python3", "tools/silabs/build_proof.py",
                           "--token", str(SCRATCH / "token.hex"),
                           "--out", str(SCRATCH / "proof.json")],
                          cwd=INTEROP, stdout=subprocess.DEVNULL)
    proof = json.loads((SCRATCH / "proof.json").read_text())

    def render(v):
        if isinstance(v, bytes):
            return v.hex()
        if isinstance(v, list):
            return [{("name" if k == 1 else "sha256" if k == 2 else "version" if k == 4 else str(k)):
                     (x.hex() if isinstance(x, bytes) else x) for k, x in c.items()} for c in v]
        return v

    return {
        "token_hex": token.hex(),
        "alg": msg.phdr and str(list(msg.phdr.values())[0].__name__ if hasattr(list(msg.phdr.values())[0], "__name__") else list(msg.phdr.values())[0]),
        "claims": {f"{k} ({CLAIM_NAMES.get(k, '?')})": render(v) for k, v in claims.items()},
        "sig_valid_vs_se_cert": True,
        "measurement": proof["measurement"],
        "measurementName": proof["measurementName"],
        "proof": proof["proof"],
    }


# ── taskboard ─────────────────────────────────────────────────────────────────

def task_list():
    n = board.functions.count().call()
    out = []
    for i in range(n):
        payload, assignee, done, sig = board.functions.get(i).call()
        out.append({"id": i, "payload": payload.decode("utf-8", "replace"),
                    "assignee": NAMES.get(bytes(assignee), bytes(assignee).hex()[:16]),
                    "done": done, "sig_len": len(sig)})
    return out


def task_run(task_id: int):
    payload, assignee, done, _ = board.functions.get(task_id).call()
    if done:
        raise RuntimeError("task already done")
    who = NAMES.get(bytes(assignee))
    if who == "pixel":
        r = phone("/sign", {"message_hex": "0x" + payload.hex()})
        result = bytes.fromhex(r["signature_der_hex"])
        detail = {"device": "pixel", "signed_with": "StrongBox node key (ECDSA-P256 DER)"}
    elif who == "silabs":
        nonce = hashlib.sha256(payload).digest()
        att = silabs_attest(nonce)
        result = bytes.fromhex(att["token_hex"])
        detail = {"device": "silabs", "signed_with": "SE PSA IAT, nonce=sha256(payload)",
                  "measurement": att["measurement"], "measurementName": att["measurementName"],
                  "proof": att["proof"]}
    else:
        raise RuntimeError(f"unknown assignee {bytes(assignee).hex()}")
    rcpt = send_tx(board.functions.submit, task_id, result)
    detail.update({"tx": rcpt.transactionHash.hex(), "result_hex": result.hex()})
    return detail


def task_verify(task_id: int):
    payload, assignee, done, sig = board.functions.get(task_id).call()
    if not done:
        return {"done": False}
    who = NAMES.get(bytes(assignee))
    out = {"done": True, "device": who, "payload": payload.decode("utf-8", "replace")}
    if who == "pixel":
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        pub = load_der_public_key(PIXEL_SPKI)
        try:
            pub.verify(bytes(sig), bytes(payload), ec.ECDSA(hashes.SHA256()))
            out["sig_valid_vs_member_key"] = True
        except InvalidSignature:
            out["sig_valid_vs_member_key"] = False
    else:
        import cbor2
        from pycose.messages import Sign1Message
        from pycose.keys import EC2Key
        from pycose.keys.curves import P256
        from cryptography.x509 import load_pem_x509_certificate
        nums = load_pem_x509_certificate(SE_PEM.read_bytes()).public_key().public_numbers()
        msg = Sign1Message.decode(bytes(sig))
        msg.key = EC2Key(crv=P256, x=nums.x.to_bytes(32, "big"), y=nums.y.to_bytes(32, "big"))
        claims = cbor2.loads(msg.payload)
        comps = {c[1]: c for c in claims[-75006]}
        out.update({
            "sig_valid_vs_se_cert": msg.verify_signature(),
            "nonce_matches_sha256_payload": claims[-75008] == hashlib.sha256(bytes(payload)).digest(),
            "live_measurement_ARoT": comps["ARoT"][2].hex(),
        })
    return out


# ── http ──────────────────────────────────────────────────────────────────────

class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(PAGE_DIR), **kw)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/info":
            st = phone("/state")
            return self._json({
                "board": BOARD, "phone": st,
                "pixel_member": PIXEL_MEMBER.hex(), "pixel_spki": PIXEL_SPKI.hex(),
                "silabs_member": SILABS_MEMBER.hex(), "silabs_xy": se_xy().hex()})
        if self.path == "/api/task/list":
            return self._json(task_list())
        super().do_GET()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(n)) if n else {}
        try:
            if self.path == "/api/pixel/attest":
                return self._json(pixel_attest())
            if self.path == "/api/silabs/attest":
                return self._json(silabs_attest(secrets.token_bytes(32)))
            if self.path == "/api/task/post":
                member = {"pixel": PIXEL_MEMBER, "silabs": SILABS_MEMBER}[body["device"]]
                rcpt = send_tx(board.functions.post, member, body["payload"].encode())
                return self._json({"tx": rcpt.transactionHash.hex(),
                                   "count": board.functions.count().call()})
            if self.path == "/api/task/run":
                return self._json(task_run(int(body["id"])))
            if self.path == "/api/task/verify":
                return self._json(task_verify(int(body["id"])))
            self.send_error(404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)


if __name__ == "__main__":
    subprocess.run(["adb", "forward", "tcp:8151", "localabstract:edgetee"], check=True)
    print(f"serving {PAGE_DIR} on http://127.0.0.1:8190")
    HTTPServer(("127.0.0.1", 8190), Handler).serve_forever()
