# `android_keyattest`

Off-chain helper for `contracts/AndroidKeyAttestationVerifier.sol`.

`build_proof.py` takes an Android Key Attestation cert chain PEM + the
challenge that was bound into the leaf, walks the leaf's Android Key
Attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`), and emits the
ABI-encoded `AndroidProof` struct that the on-chain verifier expects.

```bash
python tools/android_keyattest/build_proof.py \
    test/fixtures/pixel6_strongbox.pem \
    "edge-tee-pixel6-first-attestation-20260520"
```

Output is hex with a `0x` prefix (forge `--ffi` convention).

## Origin of the test fixture

`test/fixtures/pixel6_strongbox.pem` is a real cert chain captured on
2026-05-20 from a Pixel 6 running Android 16 with locked bootloader
(`ro.boot.flash.locked=1`) and verified boot green
(`ro.boot.verifiedbootstate=green`). Captured via the small APK in
`<edge-tee>/pixel-attest/app/` which calls:

```java
KeyGenParameterSpec.Builder(alias, PURPOSE_SIGN)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
    .setAttestationChallenge(challenge)
    .setIsStrongBoxBacked(true)
```

then `KeyStore.getCertificateChain(alias)`.

## Skeleton status

This branch wires the full proof shape end-to-end (Python builder ↔
Solidity verifier ↔ tests) but leaves two integration points stubbed:

- `_verifyChain` — on-chain ECDSA-P256/P384 + RSA-PKCS1v15 verification of the
  X.509 chain. Pixel-6-era chains are P-256 leaf + intermediates, root is
  either P-256 or P-384. Existing on-chain implementations (e.g.
  automata-network/dcap-attestation, ZeroPool's P-256 ecrecover) can be lifted
  in without touching the surrounding logic.
- `_challengeMatchesLeaf` — re-parse the leaf's attestation extension on-chain
  and compare against `proof.challenge`. For now the Python builder asserts
  this equality before encoding.

The policy enforcement on parsed fields (`verifiedBootState`, `deviceLocked`,
`appCertSha256`, `osPatchLevel`) is fully active and covered by the
companion Foundry tests.
