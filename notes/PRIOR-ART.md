# Prior art for permissionless Pixel attestation on-chain

What's been done, what hasn't, and what we're filling. Compiled May 2026.

## The slot we're filling

**(Full Android Key Attestation X.509 chain verification on-chain) × (Solidity sink) × (sideloaded, no-store-distribution permissionless tag).** Adjacent projects occupy every neighboring slot; none occupy this intersection.

## Direct prior art

### GrapheneOS Auditor + AttestationServer

- Source: [Auditor](https://github.com/GrapheneOS/Auditor), [AttestationServer](https://github.com/GrapheneOS/AttestationServer), [public verifier](https://attestation.app/about), [compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide).
- Local copy: `notes/refs/grapheneos-AttestationProtocol.java` (1735 lines, protocol v7), `notes/refs/grapheneos-AttestationServer-readme.md`.

**What it is.** An Android app that performs end-to-end Android Key Attestation chain verification, with two clever architectural choices:

1. **TOFU pinning.** First pairing pins the auditee's persistent hardware-backed key, the cert chain, the verifiedBootKey, and OS/vendor/boot patch levels. Every subsequent round requires byte-equal chain match, exact pinned-VB-key match, and monotonic-non-decreasing patch levels (downgrade detection). Hot path is one ECDSA verification — no chain re-validation.
2. **Hardcoded verifiedBootKey fingerprint table.** Lines 266–488 of `AttestationProtocol.java`: a curated `{fingerprint → (device_model, OS_variant)}` table covering Pixel 4 through Pixel 10 Pro Fold, plus GrapheneOS-as-non-stock keys baked in.

**Use cases they articulate** (from `attestation.app/about`):
1. Pairwise TOFU verification: device A audits device B; both owned by the same user.
2. Scheduled self-attestation: phone posts to `attestation.app`, which emails the same user on failure.

That's it. They are categorically silent on P2P networks, IoT, TEE coprocessors, blockchain consumers, edge applications. Their pairing key deliberately deletes on app uninstall (privacy policy: *"These keys are automatically removed when the app is uninstalled or app data is cleared"*) — incompatible with persistent cross-context identity by design.

**Relation to our design.** Same primitive (AKA chain verification with extension parsing), different sink and trust model. Their sink is the user's email inbox; ours is a smart contract. Their identity is ephemeral; ours is persistent within an RKP rotation period. They wouldn't flag our pattern as misuse — they have no architecture to lend us for the P2P/coprocessor framing.

**Worth borrowing**: TOFU pinning (would make our verifier ~500× cheaper after first attestation), the verifiedBootKey allowlist pattern (they curate at [grapheneos.org/attestation.json](https://grapheneos.org/attestation.json)), the "only certs[1] carries the extension" hardening rule.

### zk-X509 — Privacy-Preserving On-Chain Identity from Legacy PKI via ZKPs

- arxiv: https://arxiv.org/abs/2603.25190

Verifies general X.509 chains (Korean NPKI, Estonian eID, German eID) inside SP1 zkVM (~12M cycles for P-256, ~17M for RSA-2048), submits a Groth16 proof to an `IdentityRegistry` Solidity contract (~300K gas). **Explicitly excludes mobile attestation chains.** Different scope: it ZK-wraps the chain validity; our design verifies the chain directly. Both Solidity sinks; both targeting real-world PKIs; non-overlapping mobile/non-mobile.

### Daimo / Clave / Coinbase Smart Wallet / Pixel-ETHGlobal-7zw9q

- [Daimo p256-verifier](https://github.com/daimo-eth/p256-verifier), [Clave EIP-7212 fallback](https://github.com/getclave/eip-7212), [Pixel hackathon project](https://ethglobal.com/showcase/pixel-7zw9q).

The ERC-4337-with-P256 family. Uses the *leaf P-256 key* from Android Keystore to sign user-ops on an account-abstraction wallet. **Never parses the attestation extension or walks the chain to Google's root.** No device-class assertion at the contract layer. Different goal: signing UX, not device attestation. We use Daimo's p256-verifier as one of our chain-link primitives but extend the work to full chain + extension parsing.

### Flashbots Sirrah / Phala / Marlin / iExec / Oasis Sapphire

- [Sirrah](https://writings.flashbots.net/suave-tee-coprocessor), [Mind the Gap](https://writings.flashbots.net/mind-the-gap-tee-poc), [Phala](https://phala.com/posts/coprocessor-security-verification-framework), [Marlin](https://github.com/marlinprotocol), [iExec](https://github.com/iExecBlockchainComputing), [Oasis Sapphire](https://oasisprotocol.org/sapphire-the-confidential-evm-paratime).

The TEE coprocessor pattern with on-chain attestation verification — cloud-only (SGX, TDX, Nitro). Flashbots' Mind the Gap post explicitly notes consumer SGX was retired and *"modern TEEs are openly branded as cloud-only."* The Messari report ([TEE: The Hardware Backbone](https://messari.io/report/tee-the-hardware-backbone-for-next-gen-onchain-experience)) catalogs the whole space and the consumer-device-TEE absence is conspicuous. We fill the consumer-end-device slot of the same architectural pattern.

### Blockene (academic — high-throughput blockchain over mobile)

- arxiv: https://arxiv.org/abs/2010.07277

The closest *academic* prior art for "use the phone's TEE as the identity anchor in an EVM-adjacent system." Smartphone-based high-throughput blockchain; TEE-attested identity = sybil-resistance for the consensus participant set; explicitly "one active identity per TEE." Not shipped, no Solidity verifier published. Validates the design but doesn't occupy the slot.

### Solana Mobile Saga / Seeker (Seed Vault)

- https://blog.solanamobile.com/post/seed-vault-wallet

Hardware-isolated seed storage with biometric authorization. Uses StrongBox-class secure elements. **Does not expose attestation chain on-chain.** The phone is a hardware wallet, not an attested oracle. Solana-only.

### Sybil-resistance stamp marketplaces (Galxe, Gitcoin/Human Passport, Holonym)

- [Galxe Passport V3](https://www.galxe.com/blog/galxe-passport-v3-the-compliance-ready-identity-layer-for-web3-growth)
- [Human Passport](https://passport.human.tech/)
- [Holonym](https://medium.com/holonym/sybil-resistant-airdrops-023710717413)

The production sybil-resistance stack. **None of them use Android Key Attestation.** Galxe = behavioral + KYC-adjacent; Gitcoin = social/identity stamps; Holonym = phone numbers + government ID over ZK. Hardware attestation conspicuously absent — there is no `phone-hardware-attestation` stamp in Gitcoin Passport's registry. **Direct gap.**

### Worldcoin / World ID

- https://world.org/world-id

Proof-of-personhood via Orb-issued iris credential, used via ZK to sign into apps. Phone stores private proof after Orb verification, but **the phone's hardware attestation chain is not the root** — the Orb is. Orthogonal to our design (different axis: "unique human" vs "genuine device").

### Cloudflare CAP (Cryptographic Attestation of Personhood) — accurate framing

- [Launch blog](https://blog.cloudflare.com/introducing-cryptographic-attestation-of-personhood/), [platform expansion](https://blog.cloudflare.com/cap-expands-support/), [current docs](https://developers.cloudflare.com/fundamentals/reference/cryptographic-personhood/).

**Did not use Android Key Attestation.** WebAuthn only — FIDO U2F roaming authenticators (YubiKey, HyperFIDO, Thetis) plus WebAuthn platform authenticators (Apple Touch ID/Face ID, Microsoft Hello, "Android Biometric Authentication"). When Android participates, it's via Chrome's WebAuthn JS API. Cloudflare's trust anchor is the **FIDO Metadata Service**, not Google's Hardware Attestation Root. The AKA chain is never parsed. CAP is the most-publicized "hardware attestation on the web" deployment, but it doesn't occupy the AKA-on-chain slot.

## Adjacent academic / theoretical work

- **Mayrhofer et al., *The Android Platform Security Model*** ([arXiv:1904.05572](https://arxiv.org/abs/1904.05572), ACM TOPS 2021) — canonical AOSP threat model. §A.1 explicitly contemplates "other parties at run-time" consuming AKA. Direct support for our framing.
- **Mayrhofer's *Attestable Builds*** ([arXiv:2505.02521](https://arxiv.org/abs/2505.02521), CCS 2025) — reproducible builds in TEEs; *advocates multi-vendor anytrust* for high-value attestation. Tension with our single-vendor (Google) pipeline, not contradiction.
- **Leierzopf, Mayrhofer et al. (IEEE CNS 2024)** — field measurement: StrongBox is on **<10% of fielded Android devices.** Useful for sybil-cost framing.
- **Schertler 2024** ([PDF on Mayrhofer's course list](https://www.mayrhofer.eu.org/courses/android-security/selected-paper/2024/Comparing_key_attestation_and_Play_Integrity_API.pdf)) — student survey framing Play Integrity as anticompetitive vs. AKA as flexible.
- **Aldoseri, Chothia, Moreira, Oswald (AsiaCCS 2023)** — formal model of Android Key Attestation. Found freshness vulnerability in Google's recommended-use pattern, Google [confirmed](https://issuetracker.google.com/205589624). Relevant to our threat model — see `THREAT-MODEL.md`.
- **GrapheneOS attestation discourse** — [compatibility guide](https://grapheneos.org/articles/attestation-compatibility-guide), [Auditor docs](https://attestation.app/about). Single principal articulating the Play-Integrity-vs-AKA layer distinction as a *vendor lock-in* concern.

## What's missing in the public discourse

1. **No public on-chain verifier for the full AKA chain.** Daimo's P-256 verifier is one primitive; nobody composed P-256 + P-384 + RSA-4096 + extension parser + Google-root pinning into a deployed Solidity contract.
2. **No public on-chain parser for the AKA extension (OID 1.3.6.1.4.1.11129.2.1.17).** Without this, contracts can verify *some chain was valid*, but cannot enforce *what* the device proved.
3. **No POAP-style hardware-attested tag.** Every adjacent project either gates on a centralized server that validates chains (defeating trustless property), or does ERC-4337 wallet-signing with the leaf key only (no device-class assertion).
4. **The "sideload + AKA = censorship-resistant attestation" argument is articulated by GrapheneOS but never connected to EVM composability.** That bridge is unwritten.

## Verdict

Our design is **the missing intersection.** Closest occupants are Daimo/Clave (different goal: AA wallets), zk-X509 (different scope: ZK-wrapped, not AKA), Sirrah/Phala/Marlin (different hardware tier: cloud-only), GrapheneOS Auditor (different sink: email). No single project covers (full-chain on-chain) × (AKA specifically) × (Solidity) × (sideload, no app store).

An SDK that exposes a clean `attestation: AndroidKeyAttestationBundle → SolidityCalldata` + audited `IAndroidKeyAttestationVerifier` Solidity primitive would not duplicate existing work — it would be the first general-purpose primitive of its kind. The risk is obsolescence not competition: RIP-7212 / EIP-7951 (P-256 precompile) is moving forward — when it lands, our verifier gets cheaper. Forcing function in our favor.
