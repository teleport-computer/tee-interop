# Threat model for the Pixel-faucet + on-chain AKA verifier

What the design protects against, what it doesn't, and where Mayrhofer's
published work tightens or loosens specific claims. Compiled from a deep read
of his corpus + adjacent formal-methods work — see `PRIOR-ART.md` and the
PDFs in `refs/`.

## What the design protects against

1. **Forged attestation chains** — the on-chain verifier performs full ECDSA-P256 + P-384 + RSA-PKCS1v15-SHA256 chain validation, terminating at a SHA-256 pin of the [Google Hardware Attestation Root](https://github.com/google/android-key-attestation/tree/master/src/main/resources). An attacker who lacks a Google-rooted chain cannot produce a valid claim.

2. **Unverified-boot / unlocked-bootloader devices** — `verifiedBootState=Verified (GREEN)` + `deviceLocked=true` are enforced on-chain via the parsed attestation extension. Locked-bootloader spoofing requires breaking the Verified Boot trust chain on a real Pixel.

3. **Challenge tampering** — the contract checks the parsed `attestationChallenge` octet-string in the leaf extension equals what the relayer signed over. The host cannot inject a different challenge into the proof envelope.

4. **Relayer dishonesty (partial)** — the relayer signs a permit that's verified on-chain (`ecrecover`). If a future operator replaces the relayer key, prior claims remain valid (their permits were signed by the historical key, which is still recoverable). The relayer cannot fabricate claims for devices it has not seen.

5. **One-per-device-per-RKP-period sybil** — `claimed[keccak256(certs[1])]` enforces one claim per StrongBox attestation-key cert. Each Pixel has one such cert per RKP period (typically a few weeks). Sybil cost ≈ buying a new Pixel ($300) or waiting ~weeks for natural RKP rotation.

6. **Worker-side gas-waste DoS (post-fix)** — the relayer pre-checks `faucet.claimed(fp)` before submitting a tx. Repeats short-circuit to a 200 OK with the original Tagged event surfaced; no doomed tx is submitted, no gas burned.

## What the design *does not* protect against

### From Mayrhofer's *Android Platform Security Model* (TOPS 2021), §4.3.8 footnote:

> *"if an attacker gains access to the low-level interfaces for communicating directly with Keymint or Strongbox, they can use it as an oracle for cryptographic operations that require the private key"*

**A kernel-compromised Pixel** can use its StrongBox key as a signing oracle. The hardware key never leaves the chip, but the *userspace* asking for signatures can be any malicious payload on a rooted device. We do **not** detect this — we trust the Android KeyStore service to honor `setIsStrongBoxBacked(true)` requests faithfully. If the system bootloader is locked + `verifiedBootState=Verified`, this is constrained to in-spec Android KeyStore behavior, but a runtime exploit of the KeyStore service itself is out of scope.

**Mitigation possible but not built**: validate `attestationApplicationId` against an allowlist of expected app signing-cert digests. We deliberately do *not* do this because it would break the "permissionless via APK sideloading" property (see below).

### From Mayrhofer §4.7.1 — YELLOW boot state is legitimate

> *"AVB implementations may also allow a user-defined VBMeta signing key K_C′ to be set… in this case, the Verified Boot state will be set to YELLOW to indicate that non-manufacturer keys were used to sign the partitions, but that verification with the user-defined keys has still been performed correctly"*

Our strict `verifiedBootState == 0 (GREEN)` policy **excludes legitimate GrapheneOS / CalyxOS / re-locked custom-root devices.** Those are arguably *more* security-conscious than stock Pixels. For broader coverage we could accept GREEN+YELLOW on separate paths (with allowlisted user-defined VBMeta roots per the [GrapheneOS compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide)). Decision deferred — current demo targets stock Pixel only.

### From Aldoseri, Chothia, Moreira, Oswald (AsiaCCS 2023) — see `refs/aldoseri-2023-asiaccs-symbolic-attestation.pdf`

Formally proved that **Google's *recommended* use of Key Attestation lacks freshness.** Google [confirmed](https://issuetracker.google.com/205589624) the issue. The recommended-use protocol fails the "Attestation Report Recentness" property.

> *"the challenge phase is missing in the official recommended practice of the protocol… an app can return an arbitrarily old attestation statement to any challenge"*

**Our exposure.** Our binding hash is `SHA256("pixel-faucet/v1" || chainId || faucet || to || sha256(message))` — deterministic, no nonce. An attacker who somehow obtained a valid chain with this binding could replay it at the chain-validity layer.

**Our mitigation (by accident, not design).** The contract's `claimed[deviceFingerprint]` mapping bounds replay to one successful claim per `certs[1]` per RKP period. Across RKP rotations, `certs[1]` rotates and the contract sees a new fingerprint — which is the *intended* one-per-Pixel-per-period behavior.

**Hardening pass**: bind a contract-derived fresh value (e.g. `blockhash(latest)`) into the binding. Then the chain itself is fresh w.r.t. the recent blockchain state, not just the contract-level mapping. Worth doing before any high-stakes consumer integrates.

### From Mayrhofer *Attestable Builds* (CCS 2025) — multi-vendor anytrust

> *"the guarantees of the [Reproducible Build] imply an anytrust model that is easily verified… as long as they trust at least one of the Confidential Computing vendors—without having to decide which one"*

Mayrhofer's recent posture is **multi-vendor anytrust** for high-value attestation flows. We are **single-vendor**: Google's HSM, Google's signing process, Google's RKP fleet, Google's CRL endpoint. Tension, not contradiction. If Google compromises any of these (key extraction, hostile root rotation, selective revocation), the entire pipeline fails.

**Out of scope**: state-level attacks on Google's HSM, hostile root rotation, selective revocation.

**Mitigation possible but not built**: add a transparency log over emitted chains, so observable rotation of the pinned root is publicly noticed.

### From Leierzopf et al. (IEEE CNS 2024) — coverage caveat

> *"the presence of 'StrongBox' is considered a critical factor… we can only guess that it is supported on less than 10% of devices"*

Our sybil-cost framing ("$300 per device per RKP period") assumes Pixel-class hardware. **<10% of fielded Android devices have StrongBox.** Burner-phone sybil at $50/device is *not* economically rational — those devices fail at the StrongBox security-level check at line 573 of GrapheneOS's Auditor. The cost gradient holds, but it's "Pixel cost" not "any Android cost." Worth being honest in any pitch.

### Physical attacks on Titan M2 itself

Mayrhofer's APS §4.3.8 footnote 27: *"Side-channel attacks such as [116] are currently out of scope of this (software) platform security model."* The paper does not document practical non-state-actor attacks on Titan M / Titan M2 attestation-key extraction. **Our framing should be**: "no public extraction of a Pixel 6 Titan M2 attestation key has been documented as of this analysis" — *not* "Titan M2 is uncompromisable." State-level extraction is out of scope, consistent with Mayrhofer's silence on the topic.

### attestationApplicationId is not validated

The leaf extension records `attestationApplicationId` (a SHA-256 of the calling app's signing cert). **We deliberately do not validate this.** Quote from APS §4.1.1: *"the app signing key is trusted implicitly upon first installation… side-loading apps is currently out of scope of the platform security model."* This is a feature for our use case (permissionless sideload), but it means:

- An on-device runtime exploit of the AndroidKeyStore service could request attestations with arbitrary `attestationApplicationId` values (subject to whatever the service actually checks).
- An honest sideloaded APK and a malicious sideloaded APK look identical to our contract.

We accept this in exchange for the no-app-store property.

## In-scope claims, restated cleanly

The contract enforces:

| Property | Where enforced | Confidence |
|---|---|---|
| Valid Google-rooted X.509 chain | on-chain (full sig verify + root pin) | high |
| `verifiedBootState == GREEN` | on-chain (extension parse) | high |
| `deviceLocked == true` | on-chain (extension parse) | high |
| Challenge binds `(chainId, faucet, to, message)` | on-chain (challenge equality + relayer permit) | high |
| One claim per `certs[1]` | on-chain (`claimed[]` mapping) | high |
| Pixel hardware actually behaved correctly | implicit, off-chain | medium |
| AndroidKeyStore service honored StrongBox | implicit, depends on locked-boot + verified state | medium |
| No state-level extraction of Google root or Pixel key | out of scope | n/a |

## What we'd build before high-stakes consumption

In rough priority order:

1. **Fresh challenge binding** — fold `blockhash(latest)` or a contract-issued nonce into the binding hash. Eliminates the Aldoseri freshness exposure at the chain layer.
2. **VerifiedBootKey allowlist** — accept GREEN + YELLOW with a curated list of user-defined VBMeta roots (start with [GrapheneOS](https://grapheneos.org/attestation.json)).
3. **TOFU pinning fast-path** — after first claim, future actions by the same device can be a single ECDSA signature (~30k gas) instead of a fresh chain verify. Pattern lifted from GrapheneOS Auditor lines 985–1013 of [grapheneos-AttestationProtocol.java](refs/grapheneos-AttestationProtocol.java).
4. **Transparency log over emitted chains** — hedge against silent root rotation; gives observers a way to notice if our pinned root quietly changes.
5. **Anonymous-credential layer** — see [PIXEL-ANON-CREDENTIAL.md](PIXEL-ANON-CREDENTIAL.md). Replaces `keccak256(certs[1])` with a nullifier derived in-circuit; unlinkable across claims.
