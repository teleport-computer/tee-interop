#!/usr/bin/env python3
"""ECIES-P256 encryption of a fresh random secret to an Android Key Attestation leaf pubkey.

Pairing demo: this script runs inside a GHA workflow whose OIDC identity is
witnessed by Sigstore. It reads an Android-attested leaf cert, extracts the
P-256 SubjectPublicKey, generates an ephemeral P-256 keypair, ECDHs against
the attested key, HKDF-derives an AES-256-GCM key, and encrypts a random
32-byte secret. The output bundle is signed by `cosign sign-blob --yes` so
anyone can verify (a) Sigstore: which workflow at which commit encrypted
this, and (b) Android Key Attestation: which Pixel device's StrongBox holds
the decryption key.

Only that specific Pixel can recover the plaintext. We include
`plaintext_sha256` so the device-side decryption can be publicly confirmed.

Usage:
  encrypt_to_attested.py <leaf-first.pem> --out bundle.json
"""
import argparse
import hashlib
import json
import secrets
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


PROTOCOL = "tee-interop/android-pair/v1"
KDF_INFO = b"tee-interop/android-pair/v1"


def load_chain(pem_path: Path) -> list[x509.Certificate]:
    text = pem_path.read_text()
    out, cur = [], []
    for line in text.splitlines():
        cur.append(line)
        if line.startswith("-----END CERTIFICATE"):
            out.append("\n".join(cur))
            cur = []
    return [x509.load_pem_x509_certificate(b.encode()) for b in out]


def encrypt_to_leaf(leaf: x509.Certificate, plaintext: bytes) -> dict:
    pub = leaf.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise SystemExit("attested leaf must hold an EC public key")
    if pub.curve.name != "secp256r1":
        raise SystemExit(f"expected secp256r1, got {pub.curve.name}")

    ephemeral = ec.generate_private_key(ec.SECP256R1())
    shared = ephemeral.exchange(ec.ECDH(), pub)

    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=KDF_INFO).derive(shared)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, None)

    att_spki = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    eph_spki = ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    leaf_der = leaf.public_bytes(serialization.Encoding.DER)

    return {
        "protocol": PROTOCOL,
        "kdf": "HKDF-SHA256",
        "kdf_info_utf8": KDF_INFO.decode(),
        "cipher": "AES-256-GCM",
        "ecdh_curve": "secp256r1",
        "attested_pubkey_spki_hex": "0x" + att_spki.hex(),
        "ephemeral_pubkey_spki_hex": "0x" + eph_spki.hex(),
        "nonce_hex": "0x" + nonce.hex(),
        "ciphertext_hex": "0x" + ct.hex(),
        "plaintext_sha256_hex": "0x" + hashlib.sha256(plaintext).hexdigest(),
        "plaintext_len": len(plaintext),
        "leaf_cert_sha256_hex": "0x" + hashlib.sha256(leaf_der).hexdigest(),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pem", type=Path, help="leaf-first PEM cert chain")
    ap.add_argument("--out", type=Path, required=True, help="output bundle JSON path")
    ap.add_argument("--plaintext-len", type=int, default=32, help="random plaintext length")
    ap.add_argument("--metadata", type=str, default=None,
                    help="optional JSON merged into the bundle (e.g. workflow context)")
    args = ap.parse_args()

    chain = load_chain(args.pem)
    if not chain:
        raise SystemExit("no certs in PEM")
    plaintext = secrets.token_bytes(args.plaintext_len)
    bundle = encrypt_to_leaf(chain[0], plaintext)
    if args.metadata:
        bundle["context"] = json.loads(args.metadata)

    args.out.write_text(json.dumps(bundle, indent=2))
    print(f"wrote {args.out}", file=sys.stderr)
    print(f"# plaintext_sha256 = {bundle['plaintext_sha256_hex']}", file=sys.stderr)
    print("# the plaintext itself is destroyed with the workflow runner.", file=sys.stderr)


if __name__ == "__main__":
    main()
