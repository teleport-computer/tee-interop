# Android attestation demo

Each verified record in `verified/issue-N.*` is the result of a real Pixel
attestation that was verified by a GitHub-hosted workflow run, then
keyless-signed via Sigstore using the workflow's GitHub OIDC identity.

This is **interop in the meaningful sense**: two unrelated CAs sign off
on a single end-to-end claim, and either could be malicious without
breaking the other.

| Anchor | What it attests | Where it's rooted |
|---|---|---|
| Android Key Attestation | a real Pixel ran our APK with locked bootloader + verified boot, and bound the issue's challenge string into the leaf | Google's attestation roots, published at <https://github.com/android/keyattestation/blob/main/roots.json> |
| Sigstore / Fulcio (via GHA OIDC) | a specific GitHub-hosted workflow run produced the verified record JSON bytes | Fulcio's CT log, rooted in the Sigstore TUF root |

A verifier with neither our infrastructure nor our keys can re-derive
everything below.

## Artifact layout for a single attestation (issue #N)

```
verified/
├── issue-N.record.json       canonical JSON record of the verified facts
├── issue-N.sigstore.json     full Sigstore bundle (cert + signature + Rekor entry)
├── issue-N.sig               raw signature  (for cosign verify-blob)
├── issue-N.crt               Fulcio signing cert  (the GHA workflow's identity)
└── issue-N.chain.pem         the original Android cert chain submitted to the issue
```

## How to independently re-verify

### Step 1 — re-verify the Sigstore signature on the record

```bash
cosign verify-blob \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "https://github.com/teleport-computer/tee-interop/.github/workflows/verify_android_attest.yml.*" \
  --bundle verified/issue-N.sigstore.json \
  verified/issue-N.record.json
```

What this proves:

- The bundle's cert is in Fulcio's CT log (so Sigstore root → Fulcio → this cert).
- The cert's identity matches our specific workflow path (so it really was
  produced by a workflow living at the path you're checking — read the YAML).
- The record JSON bytes are exactly what was signed.

### Step 2 — re-verify the Android attestation chain

Read `issue-N.record.json` for the cherry-picked summary, but to re-derive
trust from scratch, run the verifier yourself against the original PEM:

```bash
# install once:
pip install cryptography eth-abi

# verify:
python tools/android_keyattest/verify.py \
    demos/android-attestations/verified/issue-N.chain.pem \
    --challenge "$(jq -r .input.expected_challenge_utf8 \
                   demos/android-attestations/verified/issue-N.record.json)"
```

What this proves:

- The cert chain validates against Google's published attestation roots
  (bundled at `tools/android_keyattest/roots.json`; original source linked above).
- The leaf carries the Android Key Attestation extension
  (OID `1.3.6.1.4.1.11129.2.1.17`).
- The leaf binds the specific challenge string that the issue body declared.
- The hardwareEnforced `rootOfTrust` says `verifiedBootState=Verified` and
  `deviceLocked=true` — the device booted Google-signed firmware with a
  locked bootloader.
- The leaf carries an `attestationApplicationId` whose `signature_digest`
  identifies which signed APK requested the attestation. Pin this if you
  care about which exact app produced it.

## What this demo does NOT prove

- **Code confidentiality.** The device ran our APK in Android user space,
  not in an SGX/TDX-style isolated enclave. The phone's owner could see
  what the app was doing while it was running.
- **No physical attack assumption.** Pixel's Titan M2 is tamper-resistant,
  but no consumer hardware claims protection against funded nation-state
  decapping. PSA Certified Level 3 / similar tier.

The demo is correctly tier-2 (publicly verifiable platform + measured boot
+ key non-extractability), not tier-1 (confidential compute).

## Why bother

For a permissionless devproof-style network, this gives every operator
*independent grounds for trust* without:

- a personally-issued certificate from us,
- an account anywhere,
- any private infrastructure to consult,
- any belief about our (or each other's) honesty.

The whole verification chain is anchored in two public CAs neither party
controls.
