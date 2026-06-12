#!/usr/bin/env python3
"""Build a SilabsVerifier proof bundle from a live Silicon Labs Secure Vault
PSA IAT (COSE_Sign1, ES256) + the device SE-leaf certificate.

The on-chain SilabsVerifier only re-checks the device signature (RIP-7212) and
that the pinned trust-anchor fingerprint is allowlisted. THIS script does the
off-chain X.509 work and extracts the signed claims, mirroring tools/.../stm32.

No fallbacks: a bad COSE signature or chain link raises.

Outputs test/fixtures/silabs/silabs_real_proof.json with:
  devicePubkeyXY      0x04||X||Y of the SE device (attestation) key
  cosePayloadDigest   SHA-256 of the COSE Sig_structure (what ES256 signs)
  r, s                device signature, split
  measurement         SHA-256 from EAT claim -75006 (ARoT app hash if secure
                      boot on, else PRoT SE-firmware hash) -- the codeId
  measurementName     which component the measurement is (ARoT / PRoT)
  nonce               EAT claim -75008 (challenge / freshness), hex
  silabsRootFingerprint  SHA-256(DER) of the pinned trust anchor
"""
import sys, json, hashlib, cbor2, argparse
from pathlib import Path
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives import hashes, serialization

HERE = Path(__file__).resolve().parents[2]
FIX = HERE / "test/fixtures/silabs"

ap = argparse.ArgumentParser()
ap.add_argument("--token", default=FIX / "token-iat.hex")
# device-identity chain, leaf first up to the self-signed root that is pinned on-chain
ap.add_argument("--chain", nargs="+",
                default=[FIX / "se.pem", FIX / "batch.pem",
                         FIX / "factory-prod.pem", FIX / "device-root-prod.pem"])
ap.add_argument("--out", default=FIX / "silabs_real_proof.json")
a = ap.parse_args()

raw = bytes.fromhex(Path(a.token).read_text().strip())

# --- device key from the SE leaf cert ---
chain = [load_pem_x509_certificate(Path(p).read_bytes()) for p in a.chain]
leaf = chain[0]
pub = leaf.public_key()
assert isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1"
xy = pub.public_bytes(serialization.Encoding.X962,
                      serialization.PublicFormat.UncompressedPoint)  # 0x04||X||Y
assert len(xy) == 65 and xy[0] == 4

# --- offline X.509: verify every link leaf -> ... -> self-signed root ---
for child, parent in zip(chain, chain[1:]):
    parent.public_key().verify(child.signature, child.tbs_certificate_bytes,
                               ec.ECDSA(child.signature_hash_algorithm))
root = chain[-1]
assert root.subject == root.issuer, "last cert in --chain must be the self-signed root"
root.public_key().verify(root.signature, root.tbs_certificate_bytes,
                         ec.ECDSA(root.signature_hash_algorithm))
from cryptography.x509.oid import NameOID
def _cn(c): return c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
print("[chain] " + " -> ".join(_cn(c) for c in chain)
      + "  (all links verified, root self-signed)")

# --- decompose COSE_Sign1: tag18 [ protected_bstr, unprotected, payload_bstr, sig ] ---
msg = cbor2.loads(raw)
if isinstance(msg, cbor2.CBORTag):
    assert msg.tag == 18; msg = msg.value
protected, _unprot, payload, sig = msg
assert len(sig) == 64, f"sig {len(sig)} != 64"
r = int.from_bytes(sig[:32], "big")
s = int.from_bytes(sig[32:], "big")

# --- Sig_structure digest = SHA-256( CBOR(["Signature1", protected, h'', payload]) ) ---
sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
digest = hashlib.sha256(sig_structure).digest()

# independently confirm (r,s) verifies over this digest with the device key
der = utils.encode_dss_signature(r, s)
pub.verify(der, sig_structure, ec.ECDSA(hashes.SHA256()))
print("[cose ] ES256 signature verified over reconstructed Sig_structure")

# --- claims ---
claims = cbor2.loads(payload)
profile = claims[-75000]
nonce = claims[-75008]
sw = claims[-75006]                       # list of {1:name, 2:hash(32), 4:ver}
comps = {c[1]: c for c in sw}
name = "ARoT" if "ARoT" in comps else "PRoT"   # prefer the app measurement
measurement = comps[name][2]
assert len(measurement) == 32
secure_boot = "ARoT" in comps   # an ARoT entry exists iff an app was secure-booted
print(f"[claim] profile={profile} components={list(comps)} -> measurement={name} "
      f"secureBoot={secure_boot}")

# --- trust anchor = the SiLabs Device Root CA (pinned on-chain) ---
root_der = root.public_bytes(serialization.Encoding.DER)
root_fp = hashlib.sha256(root_der).digest()
print(f"[anchor] {root.subject.rfc4514_string()} fp={root_fp.hex()}")

# abi-encoded proof, ready for cast/anvil: (bytes,bytes32,bytes32,bytes32,bytes32,bytes,bool,bytes32)
from eth_abi import encode as abi_encode
proof = abi_encode(
    ["bytes", "bytes32", "bytes32", "bytes32", "bytes32", "bytes", "bool", "bytes32"],
    [xy, digest, r.to_bytes(32, "big"), s.to_bytes(32, "big"), measurement, nonce,
     secure_boot, root_fp])

out = {
    "devicePubkeyXY": "0x" + xy.hex(),
    "cosePayloadDigest": "0x" + digest.hex(),
    "r": "0x%064x" % r,
    "s": "0x%064x" % s,
    "measurement": "0x" + measurement.hex(),
    "measurementName": name,
    "nonce": "0x" + nonce.hex(),
    "secureBoot": secure_boot,
    "silabsRootFingerprint": "0x" + root_fp.hex(),
    "proof": "0x" + proof.hex(),
    "_anchorSubject": root.subject.rfc4514_string(),
    "_profile": profile,
}
Path(a.out).write_text(json.dumps(out, indent=2) + "\n")
print(f"\n[ok] wrote {a.out}")
print(json.dumps({k: v for k, v in out.items() if k != "proof"}, indent=2))
