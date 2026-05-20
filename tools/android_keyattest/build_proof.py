#!/usr/bin/env python3
"""Build an ABI-encoded AndroidProof for AndroidKeyAttestationVerifier.

Reads a PEM cert chain (Android Key Attestation, leaf-first) plus the
attestation challenge that was bound into the leaf, walks the leaf's
Android Key Attestation extension (OID 1.3.6.1.4.1.11129.2.1.17), and
emits hex-encoded `abi.encode(AndroidProof)` to stdout.

Usage:
    build_proof.py <chain.pem> <challenge-string>

Designed to be called from `forge test --ffi`. The Solidity decoder is
in contracts/AndroidKeyAttestationVerifier.sol::AndroidProof.
"""
import argparse
import hashlib
import sys
from pathlib import Path

from cryptography import x509
from eth_abi import encode

KEY_ATTESTATION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")


def parse_length(data: bytes, off: int):
    b = data[off]; off += 1
    if b < 0x80:
        return b, off
    n = b & 0x7F
    return int.from_bytes(data[off:off + n], "big"), off + n


def walk_tlvs(data: bytes):
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
        length, off = parse_length(data, off)
        yield cls, tag, data[off:off + length]
        off += length


def load_chain(pem_path: Path) -> list[x509.Certificate]:
    text = pem_path.read_text()
    out, cur = [], []
    for line in text.splitlines():
        cur.append(line)
        if line.startswith("-----END CERTIFICATE"):
            out.append("\n".join(cur))
            cur = []
    return [x509.load_pem_x509_certificate(b.encode()) for b in out]


def parse_leaf_extension(leaf: x509.Certificate) -> dict:
    ext = leaf.extensions.get_extension_for_oid(KEY_ATTESTATION_OID)
    raw = ext.value.value
    outer = list(walk_tlvs(raw))
    assert outer[0][1] == 16, "expected outer SEQUENCE"
    fields = list(walk_tlvs(outer[0][2]))

    attest_security_level = fields[1][2][0]
    keymint_security_level = fields[3][2][0]
    challenge = fields[4][2]

    hw_body = fields[7][2]
    # software-enforced authlist is fields[6]; attestationApplicationId lives there.
    sw_body = fields[6][2]

    parsed = {
        "attestSecLevel": attest_security_level,
        "keyMintSecLevel": keymint_security_level,
        "verifiedBootState": 3,  # Failed; overridden if present
        "deviceLocked": False,
        "verifiedBootHash": b"\x00" * 32,
        "verifiedBootKey": b"\x00" * 32,
        "appCertSha256": b"\x00" * 32,
        "osPatchLevel": 0,
        "challenge": challenge,
    }

    # Walk the HW authlist for rootOfTrust (tag 704) and osPatchLevel (tag 706).
    for cls, tag, value in walk_tlvs(hw_body):
        if cls != 2:
            continue
        inner = list(walk_tlvs(value))
        if not inner:
            continue
        _, inner_tag, inner_val = inner[0]
        if tag == 704:  # rootOfTrust
            rot = list(walk_tlvs(inner_val))
            parsed["verifiedBootKey"] = (rot[0][2] + b"\x00" * 32)[:32]
            parsed["deviceLocked"] = bool(rot[1][2][0])
            parsed["verifiedBootState"] = rot[2][2][0]
            parsed["verifiedBootHash"] = (rot[3][2] + b"\x00" * 32)[:32]
        elif tag == 706:  # osPatchLevel (YYYYMM as INTEGER)
            parsed["osPatchLevel"] = int.from_bytes(inner_val, "big")

    # Walk the SW authlist for attestationApplicationId (tag 709) -> SEQUENCE of
    # { SET OF AttestationPackageInfo, SET OF OCTET_STRING signatureDigest }.
    for cls, tag, value in walk_tlvs(sw_body):
        if cls != 2 or tag != 709:
            continue
        inner = list(walk_tlvs(value))
        if not inner:
            continue
        # The single OCTET STRING inside the EXPLICIT wrapper holds the
        # DER-encoded AttestationApplicationId SEQUENCE.
        appid_body = inner[0][2]
        # Some versions encode the value as OCTET STRING -> SEQUENCE inside;
        # others as SEQUENCE directly. Tolerate both.
        if inner[0][1] == 4:  # OCTET STRING
            appid_seq, = list(walk_tlvs(appid_body))[:1]
            appid_body = appid_seq[2]
        # Second element of the SEQUENCE is SET OF OCTET STRING (cert digests).
        seq_elements = list(walk_tlvs(appid_body))
        if len(seq_elements) >= 2:
            sig_set = seq_elements[1][2]
            digests = list(walk_tlvs(sig_set))
            if digests:
                parsed["appCertSha256"] = digests[0][2]
        break

    return parsed


def leaf_subject_pubkey(leaf: x509.Certificate) -> bytes:
    # Re-DER the SubjectPublicKeyInfo so on-chain code can extract the X9.62
    # uncompressed point. For EC keys, x509 gives us pubkey().public_bytes(
    # encoding=DER, format=SubjectPublicKeyInfo); we keep the SPKI envelope
    # so the on-chain parser knows the curve.
    from cryptography.hazmat.primitives import serialization
    return leaf.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_proof(pem_path: Path, challenge: bytes) -> bytes:
    chain = load_chain(pem_path)
    if not chain:
        raise SystemExit("empty PEM chain")
    leaf = chain[0]
    parsed = parse_leaf_extension(leaf)

    if parsed["challenge"] != challenge:
        raise SystemExit(
            f"challenge mismatch — leaf has {parsed['challenge']!r}, expected {challenge!r}"
        )

    certs_der = [c.public_bytes(__import__("cryptography").hazmat.primitives.serialization.Encoding.DER) for c in chain]

    # ParsedKeyDescription tuple — order matches the Solidity struct field order.
    parsed_tuple = (
        parsed["attestSecLevel"],
        parsed["keyMintSecLevel"],
        parsed["verifiedBootState"],
        parsed["deviceLocked"],
        parsed["verifiedBootHash"],
        parsed["verifiedBootKey"],
        parsed["appCertSha256"],
        parsed["osPatchLevel"],
        leaf_subject_pubkey(leaf),
    )

    # AndroidProof tuple
    proof_tuple = (certs_der, challenge, parsed_tuple)

    return encode(
        ["(bytes[],bytes,(uint8,uint8,uint8,bool,bytes32,bytes32,bytes32,uint32,bytes))"],
        [proof_tuple],
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pem", type=Path, help="cert chain PEM, leaf-first")
    ap.add_argument("challenge", type=str, help="expected challenge string")
    args = ap.parse_args()
    proof = build_proof(args.pem, args.challenge.encode())
    # forge test --ffi expects bare hex with 0x prefix, no trailing newline.
    sys.stdout.write("0x" + proof.hex())


if __name__ == "__main__":
    main()
