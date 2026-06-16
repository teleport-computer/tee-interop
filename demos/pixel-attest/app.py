"""Flask demo for Pixel 6a Android Key Attestation.

Phone communicates via ADB-forwarded Unix socket:
    adb forward tcp:7340 localabstract:edgetee

Endpoints:
    /              UI
    /api/status    device info + connection check
    /api/attest    POST {nonce} → verify full chain, return all fields
    /api/challenge GET → fresh nonce for phone-calls-CVM flow
    /api/submit    POST {nonce, chain, apk_hash} → CVM verifies bundle

Run:
    PIXEL_MOCK=1 python3 app.py          # synthetic, no phone
    python3 app.py                       # live phone (adb forward must be active)
"""
import hashlib, json, os, secrets, sys, time
from pathlib import Path
from flask import Flask, jsonify, render_template, request

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "tools" / "android_keyattest"))
import verify

app = Flask(__name__)
MOCK = os.environ.get("PIXEL_MOCK") == "1"
PHONE_URL = "http://localhost:7340"
MOCK_NONCE = "MOCK0000"
MOCK_FILE = Path(__file__).resolve().parent / "mock_attest.json"

PINNED_VBHASH  = "jFTAie9v+d0PZZCVbEl4KxYURdXXLqsM9+ywm5QmB54="
PINNED_PACKAGE = "com.edgetee.attest"

def _mock_status():
    return {"device": "Pixel 6a (mock)", "android": "16",
            "socket": "edgetee", "status": "ok", "mock": True}

def _mock_attest(nonce: str):
    d = json.loads(MOCK_FILE.read_text())
    return d["chain"], d["apk_hash"], MOCK_NONCE

def _phone_status():
    import urllib.request
    with urllib.request.urlopen(PHONE_URL + "/", timeout=3) as r:
        return json.loads(r.read())

def _phone_attest(nonce: str):
    import urllib.request
    body = json.dumps({"challenge": nonce}).encode()
    req = urllib.request.Request(
        PHONE_URL + "/attest", data=body,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        resp = json.loads(r.read())
    return resp["chain"], resp["apk_hash"]

def _verify_chain(pem_text: str, nonce: str, apk_hash: str):
    import base64, tempfile
    roots = verify.load_google_roots()

    with tempfile.NamedTemporaryFile(suffix=".pem", mode="w", delete=False) as f:
        f.write(pem_text); tmp = f.name
    try:
        chain = verify.load_chain(Path(tmp))
    finally:
        os.unlink(tmp)

    checks = []

    try:
        root_subject = verify.verify_chain(chain, roots)
        checks.append({"id": "chain", "ok": True,
                        "label": "Chain to Google attestation root",
                        "detail": f"cert[{len(chain)-1}] signed by {root_subject}"})
    except Exception as e:
        checks.append({"id": "chain", "ok": False,
                        "label": "Chain to Google attestation root", "detail": str(e)})
        return None, checks

    attest = verify.parse_attestation_ext(chain[0])

    is_sb = attest["attestationSecurityLevel"] == "StrongBox"
    checks.append({"id": "strongbox", "ok": is_sb,
                   "label": "StrongBox (Titan M2) security level",
                   "detail": f"attestationSecurityLevel = {attest['attestationSecurityLevel']}"})

    rot = attest["hardwareEnforced"].get("rootOfTrust", {})
    locked = rot.get("deviceLocked", False)
    vbs = rot.get("verifiedBootState", "?")
    checks.append({"id": "locked", "ok": locked and vbs in ("Verified", "SelfSigned"),
                   "label": "Locked bootloader + verified boot",
                   "detail": f"deviceLocked={locked}  verifiedBootState={vbs}"})

    got_vbhash = rot.get("verifiedBootHash", "")
    vbhash_ok = got_vbhash == PINNED_VBHASH
    checks.append({"id": "vbhash", "ok": vbhash_ok,
                   "label": "OS image pinned (verifiedBootHash)",
                   "detail": f"{got_vbhash[:24]}… {'✓' if vbhash_ok else '✗ expected ' + PINNED_VBHASH[:24] + '…'}"})

    expected_challenge_bytes = hashlib.sha256(nonce.encode("utf-8") + bytes.fromhex(apk_hash)).digest()
    raw_challenge = attest["attestationChallenge"]
    if isinstance(raw_challenge, str):
        raw_challenge = base64.b64decode(raw_challenge)
    challenge_ok = raw_challenge == expected_challenge_bytes
    checks.append({"id": "apkhash", "ok": challenge_ok,
                   "label": "APK code-hash bound in attestation challenge",
                   "detail": f"SHA-256(nonce ‖ apk_hash) {'✓' if challenge_ok else '✗'}  apk={apk_hash[:16]}…"})

    return attest, checks

@app.route("/")
def index():
    return render_template("index.html", pinned_vbhash=PINNED_VBHASH,
                           pinned_package=PINNED_PACKAGE, mock=MOCK)

@app.route("/api/status")
def api_status():
    if MOCK:
        return jsonify({**_mock_status(), "pinned_vbhash": PINNED_VBHASH})
    try:
        info = _phone_status()
        return jsonify({**info, "pinned_vbhash": PINNED_VBHASH, "mock": False})
    except Exception as e:
        return jsonify({"error": str(e), "hint": "run: adb forward tcp:7340 localabstract:edgetee"}), 503

@app.route("/api/attest", methods=["POST"])
def api_attest():
    nonce = request.get_json(force=True).get("nonce") or secrets.token_hex(16)
    t0 = time.time()

    if MOCK:
        pem, apk_hash, nonce = _mock_attest(nonce)
    else:
        try:
            pem, apk_hash = _phone_attest(nonce)
        except Exception as e:
            return jsonify({"error": str(e)}), 503

    attest, checks = _verify_chain(pem, nonce, apk_hash)
    elapsed_ms = round((time.time() - t0) * 1000)

    rot = (attest or {}).get("hardwareEnforced", {}).get("rootOfTrust", {})
    return jsonify({
        "nonce": nonce,
        "apk_hash": apk_hash,
        "elapsed_ms": elapsed_ms,
        "checks": checks,
        "all_ok": all(c["ok"] for c in checks),
        "fields": {
            "verifiedBootHash":   rot.get("verifiedBootHash", ""),
            "verifiedBootState":  rot.get("verifiedBootState", ""),
            "deviceLocked":       rot.get("deviceLocked", False),
            "osVersion":          (attest or {}).get("hardwareEnforced", {}).get("osVersion"),
            "osPatchLevel":       (attest or {}).get("hardwareEnforced", {}).get("osPatchLevel"),
            "attestationVersion": (attest or {}).get("attestationVersion"),
            "package": PINNED_PACKAGE,
        },
        "mock": MOCK,
    })

@app.route("/api/challenge")
def api_challenge():
    return jsonify({"nonce": secrets.token_hex(16)})

@app.route("/api/submit", methods=["POST"])
def api_submit():
    body = request.get_json(force=True)
    nonce    = body.get("nonce", "")
    pem      = body.get("chain", "")
    apk_hash = body.get("apk_hash", "")
    if not (nonce and pem and apk_hash):
        return jsonify({"error": "missing nonce, chain, or apk_hash"}), 400
    t0 = time.time()
    attest, checks = _verify_chain(pem, nonce, apk_hash)
    return jsonify({
        "all_ok": all(c["ok"] for c in checks),
        "checks": checks,
        "elapsed_ms": round((time.time() - t0) * 1000),
        "apk_hash": apk_hash,
        "nonce": nonce,
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5360))
    mode = "SYNTHETIC (PIXEL_MOCK=1)" if MOCK else f"LIVE → {PHONE_URL}"
    print(f"Pixel 6a attestation demo → http://127.0.0.1:{port}   [{mode}]")
    app.run(host="127.0.0.1", port=port, debug=False)
