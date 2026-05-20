---
name: Android attestation
about: Submit a Pixel / Titan M2 attestation to be verified by GitHub Actions + Sigstore
title: "Attest: <short description>"
labels: ["attest-me"]
---

<!-- Edit the `challenge:` line below to anything unique. Whatever you put here MUST match
     the challenge you give the app on your phone (setAttestationChallenge). -->

challenge: edge-tee-demo-CHANGEME

### How this works

1. Edit `challenge:` above to your chosen string.
2. Open this issue (the `attest-me` label is added automatically).
3. Open the EdgeTee Attest app, paste the same challenge, tap **Attest**.
4. Long-press the PEM output → **Share** or **Copy**.
5. Paste the PEM as a **comment** on this issue (no surrounding text needed).
6. A GitHub Action verifies the chain against Google's published roots, signs the verified
   record with the workflow's Sigstore identity, and posts the result back.

Anyone reading this issue later can independently re-verify the result against Fulcio's
CT log. See `demos/android-attestations/README.md` for the exact `cosign verify-blob`
command.
