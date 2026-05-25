# Reference materials

Raw sources cited from `PRIOR-ART.md` and `THREAT-MODEL.md`. Stashed here so
they survive `/tmp` cleanup and the original URLs going stale.

## Mayrhofer corpus

- `mayrhofer-2021-android-platform-security-model.pdf` — *The Android Platform Security Model*, Mayrhofer/Vander Stoep/Brubaker/Kralevich et al., ACM TOPS 2021 / [arXiv:1904.05572](https://arxiv.org/abs/1904.05572). The canonical AOSP threat model.
- `hugenroth-mayrhofer-2025-attestable-builds.pdf` — Hugenroth/Lins/Mayrhofer/Beresford, CCS 2025 / [arXiv:2505.02521](https://arxiv.org/abs/2505.02521). Reproducible builds in cloud TEEs; advocates multi-vendor anytrust.
- `mayrhofer-2023-momm-keynote.pdf` — Mayrhofer's MoMM 2023 Bali keynote: *The Android Platform Security Model and the Security of Actual Devices.*
- `leierzopf-mayrhofer-2024-android-device-security.pdf` — Leierzopf/Mayrhofer/Roland/Thomas, IEEE CNS 2024. Field measurement: <10% StrongBox coverage.

## Adjacent academic

- `aldoseri-2023-asiaccs-symbolic-attestation.pdf` — Aldoseri/Chothia/Moreira/Oswald, AsiaCCS 2023, *Symbolic modelling of remote attestation protocols for device and app integrity on Android.* Formally proved freshness gap in Google's recommended-use AKA protocol. [Google issue #205589624](https://issuetracker.google.com/205589624) confirmed.
- `schertler-2024-key-attestation-vs-play-integrity.pdf` — Bernhard Schertler (JKU Linz), 2024 student paper on Mayrhofer's [course list](https://www.mayrhofer.eu.org/courses/android-security/selected-paper/2024/Comparing_key_attestation_and_Play_Integrity_API.pdf). Compares AKA vs Play Integrity API, frames Play Integrity as anticompetitive.

## GrapheneOS Auditor

- `grapheneos-AttestationProtocol.java` — the canonical Auditor protocol implementation (v7, ECDSA P-256/SHA-256, TOFU pinning + downgrade detection). 1735 lines. From [GrapheneOS/Auditor](https://github.com/GrapheneOS/Auditor).
- `grapheneos-AttestationServer-readme.md` — wire format + deployment notes. From [GrapheneOS/AttestationServer](https://github.com/GrapheneOS/AttestationServer).
