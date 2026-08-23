#!/usr/bin/env python3
"""Build an on-chain proof for Stm32SecureManagerVerifier from a live H573 EAT.

Inputs are three files produced by the edge-tee STM32H5 work:

  eat.hex        the PSA token dumped by SMAK_Appli's Initial Attestation menu
  leaf.pem       the DUA initial-attestation certificate, reconstructed from a
                 512-byte SWD read of PACK1 (0x0BF9FE00) — no firmware needed
  ca_pub.pem     the ST initial-attestation CA public key

The CA key is *determined*, not published: ST licenses that certificate, but a
P-256 signature plus its message pins the signer to two candidates, and
intersecting two independent leaves leaves one. The two leaves used were a die we
own and the example certificate in UM3254 Rev 8 Figure 7, so anyone with the
public user manual and any H573 can re-derive it.

Everything is verified here before it is encoded, so a bad fixture fails locally
rather than on-chain:

  * the leaf's signature verifies under the CA key   (chain, depth 2)
  * the EAT's signature verifies under the leaf's IAK (token)
  * the claims parse and NSPE is present

    python3 build_proof.py eat.hex leaf.pem ca_pub.pem [-o out.json]
"""
import argparse
import binascii
import hashlib
import json
import sys

import cbor2
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

X962 = (serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
CLAIM_LIFECYCLE, CLAIM_SW_COMPONENTS, CLAIM_NONCE = -75002, -75006, -75008
LIFECYCLE_SECURED = 0x3000
# Which -75006 component carries the operator's own application.
APP_COMPONENT = "NSPE"


def build(eat_hex_path: str, leaf_path: str, ca_path: str) -> dict:
    token = binascii.unhexlify("".join(open(eat_hex_path).read().split()))
    leaf = x509.load_pem_x509_certificate(open(leaf_path, "rb").read())
    ca = serialization.load_pem_public_key(open(ca_path, "rb").read())

    # --- token ---
    msg = cbor2.loads(token)
    if getattr(msg, "tag", None) != 18:
        raise SystemExit("not a COSE_Sign1 (expected CBOR tag 18)")
    protected, _unprotected, payload, sig = msg.value
    if len(sig) != 64:
        raise SystemExit(f"expected a 64-byte P-256 signature, got {len(sig)}")
    sig_structure = cbor2.dumps(["Signature1", protected, b"", payload])
    cose_digest = hashlib.sha256(sig_structure).digest()
    eat_r, eat_s = sig[:32], sig[32:]

    # --- chain: leaf signed by the pinned CA ---
    ca.verify(leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
    leaf_r, leaf_s = decode_dss_signature(leaf.signature)
    leaf_digest = hashlib.sha256(leaf.tbs_certificate_bytes).digest()

    # --- token signed by the IAK in that leaf ---
    iak = leaf.public_key()
    iak.verify(encode_dss_signature(int.from_bytes(eat_r, "big"),
                                    int.from_bytes(eat_s, "big")),
               sig_structure, ec.ECDSA(hashes.SHA256()))

    # --- claims ---
    claims = cbor2.loads(payload)
    components = {c.get(1): c for c in claims.get(CLAIM_SW_COMPONENTS, [])}
    if APP_COMPONENT not in components:
        raise SystemExit(
            f"no {APP_COMPONENT} component in claim {CLAIM_SW_COMPONENTS}; present: "
            f"{sorted(components)}. The application measurement only appears once "
            f"the app is installed by SMuRoT.")
    measurement = components[APP_COMPONENT][2]
    lifecycle = claims[CLAIM_LIFECYCLE]
    nonce = claims.get(CLAIM_NONCE, b"")

    ca_pub = ca.public_bytes(*X962)
    return {
        "stCaPubkeyXY": ca_pub.hex(),
        "stCaFingerprint": hashlib.sha256(ca_pub).hexdigest(),
        "iakPubkeyXY": iak.public_bytes(*X962).hex(),
        "leafTbsDigest": leaf_digest.hex(),
        "leafR": f"{leaf_r:064x}",
        "leafS": f"{leaf_s:064x}",
        "cosePayloadDigest": cose_digest.hex(),
        "eatR": eat_r.hex(),
        "eatS": eat_s.hex(),
        "measurement": measurement.hex(),
        "nonce": nonce.hex(),
        "lifecycle": lifecycle,
        "_leafSubject": leaf.subject.rfc4514_string(),
        "_leafIssuer": leaf.issuer.rfc4514_string(),
        "_components": {k: v[2].hex() for k, v in components.items()},
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("eat"); ap.add_argument("leaf"); ap.add_argument("ca")
    ap.add_argument("-o", "--out")
    args = ap.parse_args()

    proof = build(args.eat, args.leaf, args.ca)

    print("offline verification passed")
    print(f"  leaf     : {proof['_leafSubject']}")
    print(f"  issuer   : {proof['_leafIssuer']}")
    print(f"  CA fp    : {proof['stCaFingerprint']}")
    print(f"  lifecycle: {proof['lifecycle']:#x}"
          f"{'  SECURED' if proof['lifecycle'] == LIFECYCLE_SECURED else '  (NOT secured)'}")
    for name, meas in proof["_components"].items():
        star = " <- app" if name == APP_COMPONENT else ""
        print(f"  {name:<5}    {meas}{star}")

    if proof["lifecycle"] != LIFECYCLE_SECURED:
        print("\nWARNING: lifecycle is not SECURED; the verifier will reject this "
              "proof unless acceptDevMode is on.", file=sys.stderr)

    if args.out:
        json.dump(proof, open(args.out, "w"), indent=2)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
