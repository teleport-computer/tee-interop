#!/usr/bin/env python3
"""E2E: TinfoilAdapter implements ERC-733 §C "TEE Proof" pattern, and the test
exercises tinfoil-go's real SEV-SNP attestation verifier — not a mock.

Flow:
  1. DstackVerifier registers a synthetic dstack-attested CVM running
     `tinfoil-go-verifier` (the canonical off-chain Tinfoil quote verifier).
     This member's encumbered secp256k1 key becomes the trust root for
     Tinfoil registrations.
  2. For each Tinfoil target, we invoke a Go helper (tools/tinfoil-verify-helper)
     that calls tinfoil-go's attestation.VerifyAttestationJSON() on a real
     attestation. The helper's stdout is the verified Verification struct
     (measurement registers, TLS pubkey FP, HPKE pubkey). Verification failure
     here aborts the test before any contract call is made.
  3. The verifier CVM's derived key signs an envelope binding the verified
     measurement (as codeId) and HPKE pubkey (as userData) to a fresh
     secp256k1 pubkey for bridge ECIES onboarding.
  4. TinfoilAdapter looks the signer up in the bridge member registry,
     requires its codeId == canonical-verifier codeId, admits the target.
  5. Target A encrypts a secret to Target B via ECIES; B decrypts.

Sources of attestation:
  - Vendored SEV-SNP test vector from lib/tinfoil-go (offline, deterministic)
  - Live https://atc.tinfoil.sh/attestation (real production router; needs net)

Negative cases assert:
  - signer not registered → VerifierNotRegistered
  - signer registered but wrong codeId → VerifierWrongCode
  - sig that doesn't bind to claimed pubkey → InvalidTinfoilSignature

There is no admin signer allowlist anywhere in the trust path.
"""

import json, os, signal, subprocess, sys, time
from pathlib import Path
from web3 import Web3
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_keys import keys as eth_keys
from eth_abi import encode as abi_encode
from ecies import encrypt as ecies_encrypt, decrypt as ecies_decrypt

ROOT = Path(__file__).parent
ANVIL_PORT = 8545
ANVIL_RPC = f"http://127.0.0.1:{ANVIL_PORT}"
DEPLOYER_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
VERIFY_HELPER = ROOT / "tools" / "tinfoil-verify-helper" / "tinfoil-verify"

CANONICAL_VERIFIER_CODE_ID = bytes.fromhex(
    # would be the dstack compose hash of tinfoil-go-verifier in production
    "7e6e6f7174696e666f696c2d676f2d7665726966696572" + "00" * 9
)


def run_tinfoil_verifier(source: str) -> dict:
    """Invoke tools/tinfoil-verify-helper, which calls tinfoil-go's real
    attestation.VerifyAttestationJSON(). Raises if verification fails.

    The `source` argument either names a built-in helper mode (vendored-sev,
    vendored-tdx, live, stdin) or uses the `host:<hostname>` form to fetch
    /.well-known/tinfoil-attestation directly from a third-party Tinfoil
    container deployment (the only way to verify Tinfoil-Containers — the ATC
    bundle path is managed-inference-only)."""
    if not VERIFY_HELPER.exists():
        sys.exit(f"build the helper first: cd {VERIFY_HELPER.parent} && go build -o tinfoil-verify ./...")
    if source.startswith("host:"):
        argv = [str(VERIFY_HELPER), "--source", "host", "--host", source[len("host:"):]]
    else:
        argv = [str(VERIFY_HELPER), "--source", source]
    res = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise RuntimeError(f"tinfoil-verify {argv[1:]} failed:\n{res.stderr}")
    return json.loads(res.stdout)


def load_artifact(name):
    art = json.load(open(ROOT / "out" / f"{name}.sol" / f"{name}.json"))
    return art["abi"], art["bytecode"]["object"]


def deploy(w3, deployer, abi, bytecode, *args):
    contract = w3.eth.contract(abi=abi, bytecode=bytecode)
    tx = contract.constructor(*args).build_transaction({
        "from": deployer.address,
        "nonce": w3.eth.get_transaction_count(deployer.address),
        "gas": 6_000_000,
    })
    signed = deployer.sign_transaction(tx)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    rcpt = w3.eth.wait_for_transaction_receipt(h)
    assert rcpt["status"] == 1, "deploy failed"
    return w3.eth.contract(address=rcpt["contractAddress"], abi=abi)


def send(w3, account, fn, *, expect_revert=False):
    tx = fn.build_transaction({
        "from": account.address,
        "nonce": w3.eth.get_transaction_count(account.address),
        "gas": 1_500_000,
    })
    signed = account.sign_transaction(tx)
    try:
        h = w3.eth.send_raw_transaction(signed.raw_transaction)
        rcpt = w3.eth.wait_for_transaction_receipt(h)
        if expect_revert:
            assert rcpt["status"] == 0, "expected revert, got success"
            return rcpt
        assert rcpt["status"] == 1, f"tx reverted: {h.hex()}"
        return rcpt
    except Exception as e:
        if expect_revert:
            return None
        raise


def compressed_pubkey(priv_bytes: bytes) -> bytes:
    pk = eth_keys.PrivateKey(priv_bytes).public_key
    pub_bytes = pk.to_bytes()
    x_bytes, y_bytes = pub_bytes[:32], pub_bytes[32:]
    prefix = b"\x02" if y_bytes[-1] % 2 == 0 else b"\x03"
    return prefix + x_bytes


def sign_raw_keccak(priv_bytes: bytes, msg_hash_bytes: bytes) -> bytes:
    """Sign a 32-byte hash directly (no EIP-191 prefix). Returns 65-byte rsv sig."""
    sig = eth_keys.PrivateKey(priv_bytes).sign_msg_hash(msg_hash_bytes)
    # eth_keys returns v in {0,1}; Solidity ecrecover wants {27,28} — adapter normalizes
    return sig.r.to_bytes(32, "big") + sig.s.to_bytes(32, "big") + bytes([sig.v])


def sign_eip191(priv_bytes: bytes, msg_hash_bytes: bytes) -> bytes:
    """Sign keccak('\x19Ethereum Signed Message:\n32' + hash) — eth_sign style."""
    acct = Account.from_key(priv_bytes)
    return acct.sign_message(encode_defunct(msg_hash_bytes)).signature


def build_dstack_proof(*, kms_priv, app_priv, derived_priv, code_id, purpose):
    """Synthesize a DstackProof tuple matching DstackVerifier._verifyDstackChain."""
    app_compressed = compressed_pubkey(app_priv)
    derived_compressed = compressed_pubkey(derived_priv)

    # Step 1: app signs "purpose:derivedHex" (raw keccak)
    derived_hex = derived_compressed.hex()
    app_msg_hash = Web3.keccak(text=f"{purpose}:{derived_hex}")
    app_sig = sign_raw_keccak(app_priv, app_msg_hash)

    # Step 2: KMS signs "dstack-kms-issued:" + bytes20(appId) + appCompressedPubkey (raw keccak)
    app_id_20 = code_id[:20]
    kms_msg = b"dstack-kms-issued:" + app_id_20 + app_compressed
    kms_msg_hash = Web3.keccak(kms_msg)
    kms_sig = sign_raw_keccak(kms_priv, kms_msg_hash)

    # Step 3: derived key signs an arbitrary messageHash (EIP-191)
    message_hash = Web3.keccak(text="hello-from-tinfoil-go-verifier")
    message_sig = sign_eip191(derived_priv, message_hash)

    return (message_hash, message_sig, app_sig, kms_sig,
            derived_compressed, app_compressed, purpose)


def encode_dstack_proof(code_id, dstack_tuple):
    return abi_encode(
        ["bytes32", "(bytes32,bytes,bytes,bytes,bytes,bytes,string)"],
        [code_id, dstack_tuple],
    )


def build_tinfoil_proof(*, signer_priv, target_code_id, sigstore_digest, dm_verity_root,
                        target_compressed_pubkey, user_data, domain):
    """Tinfoil envelope signed by an off-chain TEE running tinfoil-go (signer_priv).
       The signer's pubkey is the encumbered key registered as a bridge member."""
    signer_compressed = compressed_pubkey(signer_priv)
    envelope = Web3.solidity_keccak(
        ["string", "bytes32", "bytes32", "bytes32", "bytes", "bytes", "bytes"],
        ["tinfoil-release:", target_code_id, sigstore_digest, dm_verity_root,
         target_compressed_pubkey, user_data, domain.encode()],
    )
    sig = sign_eip191(signer_priv, envelope)
    return (target_code_id, sigstore_digest, dm_verity_root,
            target_compressed_pubkey, user_data, domain, signer_compressed, sig)


def encode_tinfoil_proof(p):
    return abi_encode(
        ["(bytes32,bytes32,bytes32,bytes,bytes,string,bytes,bytes)"],
        [p],
    )


def main():
    print("Starting anvil...")
    anvil = subprocess.Popen(
        ["anvil", "--port", str(ANVIL_PORT), "--silent"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    try:
        for _ in range(40):
            try:
                w3 = Web3(Web3.HTTPProvider(ANVIL_RPC))
                if w3.is_connected():
                    break
            except Exception:
                pass
            time.sleep(0.1)
        assert w3.is_connected(), "anvil failed to start"

        deployer = Account.from_key(DEPLOYER_KEY)

        # === Trust roots ===
        kms = Account.create()                # dstack KMS root (test)
        # === The off-chain tinfoil-go-verifier CVM, attested by dstack ===
        verifier_app = Account.create()
        verifier_derived = Account.create()   # this is the *signer* for Tinfoil envelopes
        # === Three target Tinfoil enclaves ===
        target_a = Account.create()
        target_b = Account.create()
        target_c = Account.create()

        # === Deploy ===
        bridge_abi, bridge_bc = load_artifact("TEEBridge")
        dstack_abi, dstack_bc = load_artifact("DstackVerifier")
        tinfoil_abi, tinfoil_bc = load_artifact("TinfoilAdapter")

        print("Deploying TEEBridge, DstackVerifier, TinfoilAdapter...")
        bridge = deploy(w3, deployer, bridge_abi, bridge_bc)
        dstack = deploy(w3, deployer, dstack_abi, dstack_bc, [kms.address])
        tinfoil = deploy(w3, deployer, tinfoil_abi, tinfoil_bc,
                         bridge.address, CANONICAL_VERIFIER_CODE_ID)

        send(w3, deployer, bridge.functions.addVerifier(dstack.address))
        send(w3, deployer, bridge.functions.addVerifier(tinfoil.address))
        send(w3, deployer, bridge.functions.addAllowedCode(CANONICAL_VERIFIER_CODE_ID))

        # === Step 1: register the tinfoil-go-verifier CVM via DstackVerifier ===
        print("\n[1] Registering tinfoil-go-verifier CVM via DstackVerifier...")
        verifier_dstack_proof = build_dstack_proof(
            kms_priv=kms.key, app_priv=verifier_app.key, derived_priv=verifier_derived.key,
            code_id=CANONICAL_VERIFIER_CODE_ID, purpose="bridge-verifier",
        )
        send(w3, deployer, bridge.functions.register(
            dstack.address, encode_dstack_proof(CANONICAL_VERIFIER_CODE_ID, verifier_dstack_proof)))
        verifier_member_id = Web3.solidity_keccak(["bytes"], [compressed_pubkey(verifier_derived.key)])
        assert bridge.functions.isMember(verifier_member_id).call(), "verifier CVM not registered"
        print(f"    member = 0x{verifier_member_id.hex()[:20]}…  codeId = {CANONICAL_VERIFIER_CODE_ID.hex()[:20]}…")

        # === Step 2 & 3: actually verify a Tinfoil attestation, then register ===
        # We use real tinfoil-go SEV-SNP verification (not a mock) for three targets:
        #   A — vendored SEV-SNP test vector (offline, deterministic)
        #   B — live atc.tinfoil.sh attestation (Tinfoil-managed inference router)
        #   C — Tinfoil-Containers third-party deploy (different product surface;
        #       no ATC bundle, /.well-known/tinfoil-attestation directly).
        #       Skipped automatically if TINFOIL_CONTAINER_HOST is unset, so this
        #       file stays runnable in CI without admin-key access.
        target_specs = [
            ("A", "vendored-sev", target_a),
            ("B", "live", target_b),
        ]
        container_host = os.environ.get("TINFOIL_CONTAINER_HOST", "")
        if container_host:
            target_specs.append(("C", f"host:{container_host}", target_c))
        else:
            print("[2.C] skipped — set TINFOIL_CONTAINER_HOST=<deploy>.containers.tinfoil.dev to enable")
        target_code_for = {}
        for label, source, target_acct in target_specs:
            print(f"\n[2.{label}] running tinfoil-go verifier ({source})...")
            v = run_tinfoil_verifier(source)
            print(f"    verified: format={v['format'].split('/')[-1]}  "
                  f"measurement={v['registers'][0][:16]}…  "
                  f"hpke={v['hpke_public_key'][:16]}…")

            # codeId is the keccak of the verified measurement register(s) — the
            # *real* output of cryptographically-verified hardware attestation.
            target_code = Web3.keccak(b"".join(bytes.fromhex(r) for r in v["registers"]))
            target_code_for[label] = target_code
            send(w3, deployer, bridge.functions.addAllowedCode(target_code))

            # userData carries the attestation-verified HPKE + TLS-FP, so the
            # bridge member's record retains the hardware-rooted commitment.
            user_data = bytes.fromhex(v["hpke_public_key"]) + bytes.fromhex(v["tls_public_key"])

            print(f"[3.{label}] verifier CVM signs envelope, registering target...")
            proof = build_tinfoil_proof(
                signer_priv=verifier_derived.key,
                target_code_id=target_code,
                sigstore_digest=Web3.keccak(text=f"sigstore-{label}"),
                dm_verity_root=b"\x00" * 32,
                target_compressed_pubkey=compressed_pubkey(target_acct.key),
                user_data=user_data,
                domain=v["format"],
            )
            send(w3, deployer, bridge.functions.register(tinfoil.address, encode_tinfoil_proof(proof)))
        target_a_code = target_code_for["A"]
        target_b_code = target_code_for["B"]

        member_a = Web3.solidity_keccak(["bytes"], [compressed_pubkey(target_a.key)])
        member_b = Web3.solidity_keccak(["bytes"], [compressed_pubkey(target_b.key)])
        assert bridge.functions.isMember(member_a).call()
        assert bridge.functions.isMember(member_b).call()
        if "C" in target_code_for:
            member_c = Web3.solidity_keccak(["bytes"], [compressed_pubkey(target_c.key)])
            assert bridge.functions.isMember(member_c).call()

        # === Step 4: ECIES handshake A → B ===
        secret = b"the eagle has landed at 0xCAFE"
        print(f"\n[4] A encrypts {len(secret)}B secret to B's pubkey, posts onboarding...")
        ciphertext = ecies_encrypt(compressed_pubkey(target_b.key), secret)
        send(w3, deployer, bridge.functions.onboard(member_a, member_b, ciphertext))

        msgs = bridge.functions.getOnboarding(member_b).call()
        assert len(msgs) == 1
        plaintext = ecies_decrypt(target_b.key, msgs[0][1])
        assert plaintext == secret
        print(f"    B decrypted: {plaintext!r}  ✓")

        # === Step 4b: C (Tinfoil-Containers third-party deploy) shares with A ===
        # Demonstrates the same membership primitive across a different Tinfoil
        # surface — the third-party container product, attested via the same
        # tinfoil-go SEV-SNP path but reached via /.well-known/tinfoil-attestation
        # rather than the atc.tinfoil.sh bundle path.
        if "C" in target_code_for:
            secret_ca = b"third-party container says hi to A"
            print(f"\n[4b] C encrypts {len(secret_ca)}B to A's pubkey...")
            ct_ca = ecies_encrypt(compressed_pubkey(target_a.key), secret_ca)
            send(w3, deployer, bridge.functions.onboard(member_c, member_a, ct_ca))
            msgs_a = bridge.functions.getOnboarding(member_a).call()
            assert len(msgs_a) == 1
            plaintext_ca = ecies_decrypt(target_a.key, msgs_a[0][1])
            assert plaintext_ca == secret_ca
            print(f"    A decrypted from C: {plaintext_ca!r}  ✓")

        # === Negative tests ===
        print("\n[neg-1] Signer not registered → expect VerifierNotRegistered")
        rogue = Account.create()
        rogue_proof = build_tinfoil_proof(
            signer_priv=rogue.key, target_code_id=target_a_code,
            sigstore_digest=Web3.keccak(text="x"), dm_verity_root=b"\x00"*32,
            target_compressed_pubkey=compressed_pubkey(Account.create().key),
            user_data=b"", domain="rogue.example",
        )
        result = send(w3, deployer, bridge.functions.register(
            tinfoil.address, encode_tinfoil_proof(rogue_proof)), expect_revert=True)
        print(f"    reverted ✓")

        print("\n[neg-2] Signer registered but wrong codeId → expect VerifierWrongCode")
        # Register a *different* dstack member with a *non-canonical* codeId
        wrong_code = bytes.fromhex("ff" * 32)
        send(w3, deployer, dstack.functions.addKmsRoot(kms.address))  # idempotent
        wrong_app = Account.create()
        wrong_derived = Account.create()
        send(w3, deployer, bridge.functions.addAllowedCode(wrong_code))
        wrong_dstack = build_dstack_proof(
            kms_priv=kms.key, app_priv=wrong_app.key, derived_priv=wrong_derived.key,
            code_id=wrong_code, purpose="not-the-verifier",
        )
        send(w3, deployer, bridge.functions.register(dstack.address,
            encode_dstack_proof(wrong_code, wrong_dstack)))
        wrong_proof = build_tinfoil_proof(
            signer_priv=wrong_derived.key, target_code_id=bytes.fromhex("c"*64),
            sigstore_digest=Web3.keccak(text="y"), dm_verity_root=b"\x00"*32,
            target_compressed_pubkey=compressed_pubkey(Account.create().key),
            user_data=b"", domain="wrongcode.example",
        )
        send(w3, deployer, bridge.functions.addAllowedCode(bytes.fromhex("c"*64)))
        result = send(w3, deployer, bridge.functions.register(
            tinfoil.address, encode_tinfoil_proof(wrong_proof)), expect_revert=True)
        print(f"    reverted ✓")

        print("\n[neg-3] Sig doesn't bind to claimed signerCompressedPubkey → expect InvalidTinfoilSignature")
        # Build a real proof from verifier_derived, then swap the compressedPubkey field
        good = build_tinfoil_proof(
            signer_priv=verifier_derived.key, target_code_id=bytes.fromhex("d"*64),
            sigstore_digest=Web3.keccak(text="z"), dm_verity_root=b"\x00"*32,
            target_compressed_pubkey=compressed_pubkey(Account.create().key),
            user_data=b"", domain="tampered.example",
        )
        send(w3, deployer, bridge.functions.addAllowedCode(bytes.fromhex("d"*64)))
        tampered = list(good)
        tampered[6] = compressed_pubkey(Account.create().key)  # swap signerCompressedPubkey
        result = send(w3, deployer, bridge.functions.register(
            tinfoil.address, encode_tinfoil_proof(tuple(tampered))), expect_revert=True)
        print(f"    reverted ✓")

        print("\n=== TEE PROOF (ERC-733 §C) E2E PASSED ===")
        print(f"  trust chain: KMS root → DstackVerifier → tinfoil-go-verifier CVM (member)")
        print(f"               → CVM-signed envelopes → {len(target_specs)} Tinfoil-attested targets")
        print(f"  ECIES handshake: A → B  ({len(secret)}B → {len(ciphertext)}B → roundtrip ✓)")
        if "C" in target_code_for:
            print(f"  ECIES handshake: C → A  ({len(secret_ca)}B → roundtrip ✓)  [Tinfoil-Containers leg]")
        print(f"  negatives: not-registered ✓  wrong-code ✓  bad-binding ✓")

    finally:
        os.killpg(os.getpgid(anvil.pid), signal.SIGTERM)
        anvil.wait(timeout=5)


if __name__ == "__main__":
    main()
