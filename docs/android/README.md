# Pixel Key Attestation is not a code-attesting TEE (retraction)

This page previously claimed *"Pixel as a publicly verifiable, permissionless
TEE"* and showed a Pixel ↔ GitHub-Actions secret exchange that was supposedly
"both sides independently verifiable." That framing is wrong. The interactive
demo has been taken down; this note records why.

## The error

Android Key Attestation never measures the app's code. The leaf's
`attestationApplicationId` binds the **package name + signing-cert digest** —
the *signer*, not the code. Two consequences, and they cover both directions:

1. **Permissionless ⇒ the signer is vacuous.** The whole pitch was "sideload
   your own APK, no developer account, no signing key from us." With no
   canonical developer, anyone signs their own APK with their own keystore and
   still gets a valid Google-rooted chain. The signer field constrains nothing.
2. **Pin a signer ⇒ no longer permissionless, and still not code.** Pinning a
   signer reintroduces a trusted developer holding that key (the Stage-0 single
   point of failure) — and even then the key-holder can ship different code
   under the same identity. Proven on real hardware: an evil twin (same package,
   same signer) that exfiltrates the challenge produces a **byte-identical**
   attestation that passes the fullest pin set. See
   `edge-tee/pixel-attest/NOTES-attestation-does-not-bind-code.md`.

## Non-extractability does not rescue the handshake demo

The demo encrypted a secret to a StrongBox-resident, non-extractable P-256 key
and claimed "only this device can decrypt — the bytes never leave the device."
Non-extractability protects the **key bytes**, not the **data**. Keystore access
is gated by app *identity* (UID / package + signer), not by code, so any code
running under that identity — including the evil twin, and with no user-auth
requirement set, silently — can use the key to ECDH-decrypt and then exfiltrate
the plaintext. The secret's confidentiality rests entirely on the APK behaving
honestly, which is the one thing attestation does not establish.

## Not the SGX / SEV-SNP / Nitro trust model

Those put a measurement of the enclave image (MRENCLAVE / launch measurement) in
the quote, so a remote party learns *what code is running*. Android Key
Attestation puts key properties + OS verified-boot state + signer identity in the
quote — never a measurement of the app. On a phone the measured boundary is the
**OS** (verified boot), not the app. Equating the two was the headline mistake.

## What a Pixel attestation genuinely establishes

- Genuine Titan M2 secure element (single die; resists bus-master substitution).
- Locked bootloader + `verifiedBootState=Verified` — Google-signed OS image.
- A challenge-bound key whose private bytes are non-extractable from the SE.
- A cert chain terminating in Google's published Hardware Attestation Root,
  verifiable on-chain (`contracts/AndroidKeyAttestationVerifier.sol` remains a
  correct *chain* verifier — it just does not verify any code).

These support **proof of genuine, unique secure hardware** — sybil resistance /
device rate-limiting — which needs no code binding. They do **not** support "a
publicly verifiable TEE that runs attested code." In ERC-733 terms this is
**Stage 0 for code integrity**: no commit binding, so it cannot anchor a
permissionless dev-proof coprocessor node.
