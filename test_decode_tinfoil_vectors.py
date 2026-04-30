#!/usr/bin/env python3
"""Decode Tinfoil's vendored test vectors to confirm they're usable as inputs
to a future on-chain SEV-SNP / TDX verifier with parity to tinfoil-go.

Vectors are inline in lib/tinfoil-go/verifier/attestation/attestation_test.go.
Body format: base64(gzip(raw_quote_bytes)).
"""
import base64, gzip

# From TestGuestVerify, SEV-SNP guest v2 case
SEV_BODY_B64 = ("H4sIAAAAAAAA/2JmgAEEixBgZGBg4AKzxEPU0eQETrU6V/UVB3t6X/nzPHnDqkuB7Ge7tj5ZEHio29Wfkc1uX"
                "9Sclq9brfxurj5f8/1vsLnEKWGd+VvbrZlW1uopNP7g1X277qF1y53Evj/F31o35j7JULPg0r0S+zF28d3utXt"
                "mKJ26X/2ndOpEHVfxXfmrpYMOEO1oGgGNBec2/VR6lX2Gl0OiQHRZX6rfLIn+iuYbKf+jFB4bqZ34TwDAwlFSk"
                "BGr+VIfV+XIhzFXsbbMitzRGPOTM8J+9sr3+qxGEkfMP1svbH7yRHSD5eb6JlZVrovx3R0LFq+9+eVA44HyWR5"
                "vlUTM+1xg5muYMzKAMIxPxyCiCHQ6e7XWK8xY82mR/JozTx04Vy5l8FSb5PHojvm2wD2bL32f4PhFweCczqKfE"
                "gb9gr/XG+Iy57HDxR1FBzhUzT5FZUW/TOHzX/fB7uei0kcHzO5v62TjbzG4Zxh1YsrdgwmpTrsN8vatoq8vRwE"
                "uAAgAAP//tiY3daAEAAA=")
EXPECTED_TLS_FP = "10ca85437a8e7353494bd4fce763b0aad25107cd8ab5e4a051c28b454f01063e"
EXPECTED_HPKE = "be5a9c84f5b53a4ed9abcf7cf7fd533718ca132c9fb5873b02a97d2e2081f80d"
EXPECTED_REG = "2dedaee13b84dc618efc73f685b16de46826380a2dd45df15da3dd8badbc9822cadf7bfc7595912c4517ba6fab1b52c0"

raw_gz = base64.b64decode(SEV_BODY_B64)
raw = gzip.decompress(raw_gz)
print(f"SEV-SNP body: {len(raw_gz)}B gzipped -> {len(raw)}B raw quote")
print(f"  first 32 bytes: {raw[:32].hex()}")
# SEV-SNP attestation_report struct is 1184 bytes; the v2 wrapper from tinfoil
# embeds the 1184B report + signature + extra context (TLS FP / HPKE pubkey).
# The TLS FP and HPKE pubkey are stored in REPORT_DATA (64 bytes) of the raw report.
# REPORT_DATA is at offset 0x50 in the SEV-SNP report.
# tinfoil-go: 32B TLS pubkey FP || 32B HPKE pubkey
report_data = raw[0x50:0x50+64]
tls_fp = report_data[:32].hex()
hpke = report_data[32:].hex()
print(f"  REPORT_DATA[0:32] (TLS FP):   {tls_fp}")
print(f"  REPORT_DATA[32:64] (HPKE):    {hpke}")
assert tls_fp == EXPECTED_TLS_FP, f"TLS FP mismatch: {tls_fp} != {EXPECTED_TLS_FP}"
assert hpke == EXPECTED_HPKE, f"HPKE mismatch: {hpke} != {EXPECTED_HPKE}"
print("  ✓ TLS FP and HPKE match expected from tinfoil-go test")

# SEV-SNP report MEASUREMENT field is at offset 0x90, 48 bytes (SHA-384)
measurement = raw[0x90:0x90+48].hex()
print(f"  MEASUREMENT (offset 0x90, 48B): {measurement}")
assert measurement == EXPECTED_REG, f"MEASUREMENT mismatch: {measurement} != {EXPECTED_REG}"
print("  ✓ MEASUREMENT matches the SEV register from tinfoil-go test")

print("\nVectors are usable: raw SEV-SNP attestation_report struct, standard layout.")
print("An on-chain verifier (e.g. Automata SEV-SNP) takes this raw byte blob directly.")
