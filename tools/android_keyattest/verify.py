#!/usr/bin/env python3
"""Verify an Android Key Attestation cert chain against Google's published roots.

Used by the verify_android_attest.yml workflow. Reads a PEM chain + an
expected challenge string, validates the X.509 chain against bundled
Google roots, parses the Android Key Attestation extension, enforces
policy gates (Verified boot state, locked bootloader, etc.), and emits
a JSON 'verified record' to stdout.

The verified record is the canonical artifact that gets cosign-signed by
the GitHub Actions workflow using GitHub's OIDC identity. The record
contains every field a downstream verifier needs to re-derive trust
without trusting either us or our infrastructure.

Usage:
    verify.py <chain.pem> --challenge <utf8-string>

Exits 0 on full verification success; nonzero on any failure.
"""
import argparse
import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

KEY_ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
SECURITY_LEVEL = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
VERIFIED_BOOT_STATE = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}

REPO_ROOT = Path(__file__).resolve().parent
ROOTS_JSON = REPO_ROOT / "roots.json"


# ---- DER walking (no schema needed) ----

def _parse_length(data: bytes, off: int):
    b = data[off]; off += 1
    if b < 0x80:
        return b, off
    n = b & 0x7F
    return int.from_bytes(data[off:off + n], "big"), off + n


def _walk_tlvs(data: bytes):
    off = 0
    while off < len(data):
        first = data[off]; off += 1
        cls = (first >> 6) & 0x3
        tag = first & 0x1F
        if tag == 0x1F:
            tag = 0
            while True:
                b = data[off]; off += 1
                tag = (tag << 7) | (b & 0x7F)
                if not (b & 0x80):
                    break
        length, off = _parse_length(data, off)
        yield cls, tag, data[off:off + length]
        off += length


# ---- chain loading + verification ----

def load_chain(pem_path: Path):
    text = pem_path.read_text()
    blocks, cur = [], []
    for line in text.splitlines():
        cur.append(line)
        if line.startswith("-----END CERTIFICATE"):
            blocks.append("\n".join(cur)); cur = []
    return [x509.load_pem_x509_certificate(b.encode()) for b in blocks]


def load_google_roots():
    roots = json.loads(ROOTS_JSON.read_text())
    return [x509.load_pem_x509_certificate(r.encode()) for r in roots]


def _verify_signed_by(child, parent):
    pub = parent.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   padding.PKCS1v15(), child.signature_hash_algorithm)
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        pub.verify(child.signature, child.tbs_certificate_bytes,
                   ec.ECDSA(child.signature_hash_algorithm))
    else:
        raise SystemExit(f"unsupported pubkey type {type(pub).__name__}")


def verify_chain(chain, roots):
    for i in range(len(chain) - 1):
        _verify_signed_by(chain[i], chain[i + 1])
    for r in roots:
        try:
            _verify_signed_by(chain[-1], r)
            return r
        except Exception:
            continue
    raise SystemExit("chain top not signed by any pinned Google attestation root")


# ---- attestation extension parsing ----

TAG_MAP = {
    1: "purpose", 2: "algorithm", 3: "keySize", 4: "blockMode", 5: "digest",
    6: "padding", 10: "ecCurve", 200: "rsaPublicExponent",
    503: "noAuthRequired", 509: "unlockedDeviceRequired",
    701: "creationDateTime", 702: "origin", 704: "rootOfTrust",
    705: "osVersion", 706: "osPatchLevel", 709: "attestationApplicationId",
    710: "attestationIdBrand", 711: "attestationIdDevice", 712: "attestationIdProduct",
    716: "attestationIdManufacturer", 717: "attestationIdModel",
    718: "vendorPatchLevel", 719: "bootPatchLevel",
}


def parse_attestation_ext(leaf):
    ext = leaf.extensions.get_extension_for_oid(KEY_ATTESTATION_OID)
    outer = list(_walk_tlvs(ext.value.value))
    body = outer[0][2]
    fields = list(_walk_tlvs(body))

    hw = parse_authlist(fields[7][2])
    sw = parse_authlist(fields[6][2])

    return {
        "attestationVersion": int.from_bytes(fields[0][2], "big"),
        "attestationSecurityLevel": SECURITY_LEVEL.get(fields[1][2][0], "?"),
        "keyMintVersion": int.from_bytes(fields[2][2], "big"),
        "keyMintSecurityLevel": SECURITY_LEVEL.get(fields[3][2][0], "?"),
        "attestationChallenge": fields[4][2],  # raw bytes
        "softwareEnforced": sw,
        "hardwareEnforced": hw,
    }


def parse_authlist(body: bytes) -> dict:
    out = {}
    for cls, tag, value in _walk_tlvs(body):
        if cls != 2:
            continue
        name = TAG_MAP.get(tag, f"tag{tag}")
        inner = list(_walk_tlvs(value))
        if not inner:
            out[name] = True; continue
        _, inner_tag, inner_val = inner[0]
        if name == "rootOfTrust":
            rot = list(_walk_tlvs(inner_val))
            out[name] = {
                "verifiedBootKey": base64.b64encode(rot[0][2]).decode(),
                "deviceLocked": bool(rot[1][2][0]),
                "verifiedBootState": VERIFIED_BOOT_STATE.get(rot[2][2][0], "?"),
                "verifiedBootHash": base64.b64encode(rot[3][2]).decode(),
            }
        elif name == "attestationApplicationId":
            # Extract first signature digest
            appid_body = inner_val if inner_tag != 4 else list(_walk_tlvs(inner_val))[0][2]
            seq_elements = list(_walk_tlvs(appid_body))
            digest = None
            if len(seq_elements) >= 2:
                digests = list(_walk_tlvs(seq_elements[1][2]))
                if digests:
                    digest = base64.b64encode(digests[0][2]).decode()
            out[name] = {"signature_digest_sha256_b64": digest}
        elif inner_tag == 5:
            out[name] = True
        elif inner_tag == 2:
            out[name] = int.from_bytes(inner_val, "big", signed=True) if inner_val else 0
        elif inner_tag == 4:
            try:
                s = inner_val.decode("utf-8")
                if s.isprintable():
                    out[name] = s; continue
            except UnicodeDecodeError:
                pass
            out[name] = base64.b64encode(inner_val).decode()
        elif inner_tag == 17:
            out[name] = [int.from_bytes(v, "big") for _, _, _, v in
                         [(c, t, v[:0], v) for c, t, v in _walk_tlvs(inner_val)]]
        else:
            out[name] = f"<tag={inner_tag}>"
    return out


# ---- policy + verified-record emission ----

def emit_record(chain, root_cert, parsed, expected_challenge: bytes, pem_path: Path):
    failures = []
    if parsed["attestationChallenge"] != expected_challenge:
        failures.append(
            f"challenge mismatch: leaf has {parsed['attestationChallenge']!r}, "
            f"expected {expected_challenge!r}"
        )

    rot = parsed["hardwareEnforced"].get("rootOfTrust", {})
    if rot.get("verifiedBootState") != "Verified":
        failures.append(f"verifiedBootState != Verified (got {rot.get('verifiedBootState')!r})")
    if not rot.get("deviceLocked"):
        failures.append("deviceLocked != True")

    if failures:
        sys.stderr.write("FAIL:\n  " + "\n  ".join(failures) + "\n")
        sys.exit(1)

    chain_sha256 = hashlib.sha256(pem_path.read_bytes()).hexdigest()

    leaf = chain[0]
    leaf_pubkey_der = leaf.public_key().public_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.DER,
        format=__import__("cryptography").hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    record = {
        "schema": "edge-tee/android-attestation-verified/v1",
        "verifier": {
            "repo": os.environ.get("GITHUB_REPOSITORY", "local"),
            "ref": os.environ.get("GITHUB_REF", ""),
            "sha": os.environ.get("GITHUB_SHA", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "actor": os.environ.get("GITHUB_ACTOR", ""),
        },
        "input": {
            "chain_pem_sha256": chain_sha256,
            "chain_length": len(chain),
            "root_cert_subject": root_cert.subject.rfc4514_string(),
            "expected_challenge_utf8": expected_challenge.decode("utf-8", errors="replace"),
            "expected_challenge_b64": base64.b64encode(expected_challenge).decode(),
        },
        "verified": {
            "attestationSecurityLevel": parsed["attestationSecurityLevel"],
            "keyMintSecurityLevel": parsed["keyMintSecurityLevel"],
            "rootOfTrust": parsed["hardwareEnforced"].get("rootOfTrust"),
            "osVersion": parsed["hardwareEnforced"].get("osVersion"),
            "osPatchLevel": parsed["hardwareEnforced"].get("osPatchLevel"),
            "vendorPatchLevel": parsed["hardwareEnforced"].get("vendorPatchLevel"),
            "bootPatchLevel": parsed["hardwareEnforced"].get("bootPatchLevel"),
            "attestationIdBrand": parsed["hardwareEnforced"].get("attestationIdBrand"),
            "attestationIdModel": parsed["hardwareEnforced"].get("attestationIdModel"),
            "attestationApplicationId": parsed["softwareEnforced"].get("attestationApplicationId"),
            "leafPubkeySpkiB64": base64.b64encode(leaf_pubkey_der).decode(),
        },
    }
    json.dump(record, sys.stdout, indent=2)
    sys.stdout.write("\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pem", type=Path)
    ap.add_argument("--challenge", required=True, help="expected challenge string (UTF-8)")
    args = ap.parse_args()

    chain = load_chain(args.pem)
    roots = load_google_roots()
    print(f"loaded {len(chain)} certs, {len(roots)} pinned roots", file=sys.stderr)

    root_cert = verify_chain(chain, roots)
    print(f"chain verified against root: {root_cert.subject.rfc4514_string()}", file=sys.stderr)

    parsed = parse_attestation_ext(chain[0])
    emit_record(chain, root_cert, parsed, args.challenge.encode("utf-8"), args.pem)


if __name__ == "__main__":
    main()
