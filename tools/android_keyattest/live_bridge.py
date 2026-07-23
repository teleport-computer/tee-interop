#!/usr/bin/env python3
"""Laptop-side bridge for the live kiosk demo.

Forwards the phone's loopback API (adb forward tcp:8151), builds on-chain
proofs from fresh attestations via build_proof.py, and serves the live demo
page (docs/android/live/) on http://127.0.0.1:8180.
"""
import hashlib, json, os, secrets, subprocess, sys, tempfile
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.request import Request, urlopen

from build_proof import build_proof

PHONE = "http://127.0.0.1:8151"
PAGE_DIR = Path(__file__).resolve().parents[2] / "docs" / "android" / "live"


def phone(path, body=None):
    req = Request(PHONE + path, data=json.dumps(body).encode() if body is not None else None,
                  method="POST" if body is not None else "GET")
    with urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def proof_from_chain(chain_pem, challenge: bytes):
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(chain_pem)
        path = Path(f.name)
    try:
        return "0x" + build_proof(path, challenge).hex()
    finally:
        os.unlink(path)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(PAGE_DIR), **kw)

    def do_POST(self):
        try:
            if self.path == "/api/attest":
                nonce = secrets.token_hex(16)
                r = phone("/attest", {"challenge": nonce})
                cert_challenge = hashlib.sha256(
                    nonce.encode() + bytes.fromhex(r["apk_hash"])).digest()
                out = {"nonce": nonce, "apk_hash": r["apk_hash"],
                       "cert_challenge": cert_challenge.hex(),
                       "proof": proof_from_chain(r["chain"], cert_challenge)}
            elif self.path == "/api/provision_proof":
                r = phone("/provision", {})
                out = {"apk_hash": r["apk_hash"], "challenge_hex": r["challenge_hex"],
                       "proof": proof_from_chain(r["chain"], bytes.fromhex(r["challenge_hex"]))}
            else:
                self.send_error(404)
                return
            body = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except Exception as e:
            body = json.dumps({"error": f"{type(e).__name__}: {e}"}).encode()
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


if __name__ == "__main__":
    subprocess.run(["adb", "forward", "tcp:8151", "tcp:8151"], check=True)
    print(f"phone API forwarded; serving {PAGE_DIR} on http://127.0.0.1:8180")
    HTTPServer(("127.0.0.1", 8180), Handler).serve_forever()
