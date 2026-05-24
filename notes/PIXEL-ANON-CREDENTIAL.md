# Anonymous credential layer on top of Pixel attestation (v2 sketch)

Status: not work for now; captured to preserve the design while it's fresh.

## Problem

The current PixelFaucet uses `keccak256(certs[1])` as the device fingerprint.
`certs[1]` is the per-device StrongBox attestation-key cert, provisioned by
Google's RKP. It rotates every few weeks, which gives some privacy (after
rotation the same Pixel claims again as a "different" device on-chain), but
inside one RKP period, repeat claims are linkable to the same physical phone
by anyone watching the chain. The relayer also publishes the full cert chain
for auditability, leaking `attestationApplicationId` etc.

We want: prove "I am some Pixel with a Google-rooted attestation chain that
has not yet claimed", without revealing *which* Pixel.

## Design

Replace `claim(deviceFingerprint, ...)` with `claim(proof, nullifier, ...)`,
where `proof` is a Groth16 (or similar) ZK proof that:

1. **Chain validity** — there exists an X.509 chain whose root SHA-256 is in
   the on-chain `allowedRootFingerprints` set, with valid ECDSA-P256 /
   ECDSA-P384 / RSA-PKCS1v15-SHA256 signatures at each link.
2. **Policy** — leaf's Android Key Attestation extension has
   `verifiedBootState=Verified`, `deviceLocked=true`, and the
   `attestationChallenge` equals the SHA-256 binding hash committed in the
   public inputs of the proof.
3. **Nullifier derivation** — `nullifier = hash(SPKI_of_certs[1])` (or any
   stable per-device value derivable from the chain). The proof asserts the
   nullifier was computed correctly from the proven chain.

The contract:
- Verifies the proof.
- Checks `!usedNullifiers[nullifier]`.
- Sets `usedNullifiers[nullifier] = true`.
- Emits `TaggedAnon(nullifier, to, message, codeId, timestamp)`. No fingerprint,
  no pemHash; the chain itself never appears on-chain.

## Properties

- **Unlinkable across the relayer**: the relayer (or anyone observing the
  on-chain tx) sees the nullifier and the proof, neither of which reveals
  the cert chain or the device identity.
- **Sybil-resistant per RKP period**: same physical Pixel, same RKP cert →
  same nullifier → second claim rejected. After RKP rotation, the nullifier
  changes (intentional — same Pixel can claim again as a new pseudonym).
- **Permissionless**: gating is hardware attestation, not an issuer
  allow-list. Any Pixel that can satisfy the policy circuit can claim.
- **Audit trail on the prover, not on chain**: the relayer (now: any prover)
  retains the chain locally; the public artifact is only the proof.

## Engineering shape

- Reuse the Sigstore-GHA-Pixel6 circuit work (RSA-4096 + ECDSA-P256 +
  ECDSA-P384 already implemented as gadgets there).
- New: P-384 and the AKA extension parse in-circuit. The extension parse is
  the hard part — DER walking in arithmetic circuits is painful but tractable
  (we already do equivalent work on-chain in `AndroidAttest.sol`).
- Verifying contract: ~250-500k gas per claim depending on circuit
  (Groth16 over BN254). Fits Base Sepolia's per-tx cap easily.
- Trusted setup: needed for Groth16. Could borrow from a shared ceremony,
  or use Plonk/Halo2 for no setup at the cost of larger proofs.

## What stays the same

- `PixelFaucet` storage shape is similar — just `usedNullifiers` instead of
  `claimed`.
- `verifiedBootKey` (or any other rootOfTrust-derived value) could be the
  nullifier basis if we want lifetime-of-device sybil instead of
  rotate-with-RKP. Same circuit, different witness.

## When to revisit

- When the Sigstore-GHA-Pixel6 demo's circuit work has a stable AKA
  extension parser we can lift.
- When the demo grows past "fun wall" and someone wants to do something
  privacy-sensitive (vote, redeem, transact) where on-chain linkability
  of the device cert is unacceptable.
