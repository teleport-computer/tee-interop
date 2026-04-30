# Tinfoil interop

[Tinfoil](https://tinfoil.sh) runs containers in TEEs (AMD SEV-SNP, Intel TDX,
NVIDIA H100/H200/B200 confidential compute) and binds the running code to a
GitHub release via Sigstore + dm-verity ("Modelwrap" attested disk). The
canonical client-side verifier is
[`tinfoilsh/tinfoil-go`](https://github.com/tinfoilsh/tinfoil-go), vendored
under `lib/tinfoil-go`. There is **no simulator mode** — verification expects
real SEV-SNP / TDX quotes.

ERC-733 Appendix C defines three on-chain verification optimization patterns
for TEE attestations:

| | On-chain certificate caching | ZK Proof | **TEE Proof** |
|---|---|---|---|
| Trust assumption | Blockchain | Blockchain + ZKVM | **Blockchain + TEE** |
| Security | Most secure | Secure | Least secure |
| Cost | Several M gas | ~250K | **Negligible** |
| Delay | None | ~20s proving | Negligible |

`TinfoilAdapter.sol` implements **TEE Proof** by composing the bridge with
itself.

## Trust chain

```
AMD/Intel root
  └─ DstackVerifier verifies a dstack CVM running tinfoil-go-verifier
       └─ that CVM's encumbered secp256k1 key is registered as bridge member M
            with codeId == verifierCodeId (the canonical tinfoil-go-verifier compose hash)
            └─ M off-chain verifies a target Tinfoil enclave's SEV-SNP / TDX quote,
               Sigstore bundle, and dm-verity root using tinfoil-go
               └─ M signs the verified envelope (codeId, sigstoreDigest, dmVerityRoot,
                  targetPubkey, userData, domain) with its encumbered key
                  └─ TinfoilAdapter.verify():
                     - ecrecover(sig) → addr
                     - addr == compressedPubkeyToAddress(p.signerCompressedPubkey)
                     - bridge.getMember(keccak256(p.signerCompressedPubkey)).codeId
                       == verifierCodeId
                     - return (target codeId, target pubkey, target userData)
```

No admin signer allowlist. Compromise of the deployer EOA cannot inject
trusted signers — the trust root is whatever `DstackVerifier` (or another
`IVerifier` if you wire one up) accepts as a CVM running the canonical
tinfoil-go-verifier image.

## Trust assumption boundaries

- **AMD/Intel root + dstack KMS root.** Same baseline as `DstackVerifier`.
- **The tinfoil-go-verifier image's correctness.** Whoever builds and publishes
  the canonical `verifierCodeId` is implicitly trusted to faithfully implement
  the SEV-SNP / TDX / Sigstore / dm-verity checks. This is the "TEE vendor
  trustworthy" assumption from ERC-733 §C.
- **Side-channel resistance of the verifier CVM.** Inherent to TEE Proof.

The pattern is structurally weaker than Path B (ZK Proof) and Path C
(certificate caching) — both of which would verify the SEV-SNP report on-chain
directly without trusting any TEE-resident verifier. Those are open work; see
[Roadmap](#roadmap).

## Files

- `contracts/TinfoilAdapter.sol` — TEE Proof adapter (reads `TEEBridge.getMember`)
- `contracts/IVerifier.sol` — ERC-733 verifier interface
- `lib/tinfoil-go/` — vendored Go verifier (the canonical reference for what
  the off-chain CVM should compute). Embeds Genoa cert chain
  (`verifier/attestation/genoa_cert_chain.pem`), SGX/TDX root
  (`sgx_root_ca.pem`), and Sigstore trusted root
  (`verifier/client/trusted_root.json`). Real SEV-SNP and TDX test vectors
  inline in `verifier/attestation/attestation_test.go`.
- `tools/tinfoil-verify-helper/` — small Go binary that links against the
  vendored `tinfoil-go` and invokes `attestation.VerifyAttestationJSON()`.
  Sources: `--source vendored-sev` (offline, deterministic),
  `--source vendored-tdx` (currently broken — base64 corruption in const,
  fixable), `--source live` (fetches `https://atc.tinfoil.sh/attestation`).
  Build: `cd tools/tinfoil-verify-helper && go build -o tinfoil-verify ./...`
- `test_e2e_bridge_tinfoil_proof.py` — anvil e2e. Invokes the Go helper for
  each target (real cryptographic SEV-SNP verification — AMD-signed report
  walked back through the Genoa cert chain via `google/go-sev-guest`).
  Verification failure aborts before any contract call. The verified
  measurement becomes the registered `codeId`; the verified HPKE/TLS
  fingerprints are recorded in `userData`. Then registers a synthetic
  dstack-attested verifier CVM, registers two Tinfoil targets through it,
  exchanges an ECIES-encrypted secret, and asserts three meaningful
  negatives (signer not registered, signer wrong codeId, sig/pubkey binding
  mismatch).
- `test_decode_tinfoil_vectors.py` — confirms the vendored vectors decode to
  standard SEV-SNP report layout (REPORT_DATA at 0x50 = TLS FP || HPKE
  pubkey, MEASUREMENT at 0x90). Useful as a starting point for Path B/C work.

## What the test actually exercises

| Layer | Real | Mocked |
|---|---|---|
| SEV-SNP cryptographic verification (AMD signature, Genoa cert chain) | ✓ via `tinfoil-go` | |
| Live production Tinfoil attestation (`atc.tinfoil.sh`) | ✓ fetched + verified | |
| Sigstore bundle check | | (would need `--source live` with full bundle path) |
| dm-verity root binding | | (set to zeros in test envelopes) |
| Verifier CVM identity (encumbered key in real dstack TEE) | | synthetic `Account.create()` |
| dstack KMS root signature | | synthetic test KMS key |

Going from "synthetic verifier CVM" to "real verifier CVM" means deploying
`tinfoil-go-verifier` as an actual dstack CVM and registering its
`/proof`-endpoint output via `register.py`. The contract code does not change.

## Roadmap

### Path B (ZK Proof)
Wrap Automata's SEV-SNP SP1 → Groth16 verifier
([automata-network/amd-sev-snp-attestation-sdk](https://github.com/automata-network/amd-sev-snp-attestation-sdk)).
~315K gas verifier; ~20s proving. Drives a real on-chain check of the SEV-SNP
report; `TinfoilAdapter` would then assert the verified `MEASUREMENT` matches
the canonical Sigstore-attested release measurement, with the dm-verity root
read from `REPORT_DATA[32:64]`. Replaces the bridge-member-lookup step with a
real cryptographic check.

### Path C (cert caching)
Direct on-chain SEV-SNP P-384 verification + Genoa cert chain caching. Several
M gas. Most expensive but no extra trust assumptions beyond AMD's root CA.
Lowest priority.

### TDX
Same shape, but the report is multi-register (MRTD + RTMR0–3) and the cert
chain is Intel's. Automata's
[automata-dcap-attestation](https://github.com/automata-network/automata-dcap-attestation)
covers it. Would slot in alongside the SEV-SNP path as a second
quote-verification backend, gated by the TDX `Document.Format` predicate type
in the Tinfoil envelope.
