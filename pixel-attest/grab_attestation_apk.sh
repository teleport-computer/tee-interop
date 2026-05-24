#!/bin/bash
# Challenge-binding attestation capture via the edgetee-attest APK.
# Installs the APK on the connected device, generates a fresh StrongBox-backed
# EC key (with PURPOSE_AGREE_KEY so the same key can later receive ECIES
# ciphertexts), pulls the resulting cert chain, and runs the local verifier
# with --require-verified-boot --challenge.
#
# Run from this directory (tee-interop/pixel-attest/).
#
# Usage:
#   ./grab_attestation_apk.sh [challenge_string] [output.pem]
#
# Defaults:
#   challenge = "edge-tee-$(date +%s%N | head -c 16)"
#   output    = pixel_attestation_<ts>.pem
set -euo pipefail

CHALLENGE="${1:-edge-tee-$(date +%s%N | head -c 16)}"
OUT="${2:-pixel_attestation_$(date +%Y%m%d_%H%M%S).pem}"

cd "$(dirname "$0")"
REPO_ROOT="$(cd .. && pwd)"

APK=app/build/edgetee-attest.apk
[ -f "$APK" ] || { echo "APK not built; run app/build.sh first."; exit 1; }

echo "--- adb device check ---"
adb devices -l
adb get-state >/dev/null 2>&1 || { echo "no device or unauthorized; check USB cable + RSA prompt on phone"; exit 1; }

echo "--- model: $(adb shell getprop ro.product.model)  android: $(adb shell getprop ro.build.version.release)"

PKG=com.edgetee.attest
REMOTE_DIR=/sdcard/Android/data/$PKG/files
REMOTE_PEM=$REMOTE_DIR/attestation.pem
REMOTE_INFO=$REMOTE_DIR/attestation.info
REMOTE_ERR=$REMOTE_DIR/attestation.err

echo "--- removing any prior output on device ---"
adb shell "rm -f $REMOTE_PEM $REMOTE_INFO $REMOTE_ERR" 2>/dev/null || true

echo "--- installing APK ---"
adb install -r "$APK"

ALIAS="edgetee-$(date +%s)"
echo "--- launching MainActivity (challenge='$CHALLENGE' alias='$ALIAS') ---"
adb shell "am start -W -n $PKG/.MainActivity \
    -e challenge \"$CHALLENGE\" \
    -e alias \"$ALIAS\" \
    -e strongbox true" >/dev/null
sleep 2

if ! adb shell "ls $REMOTE_PEM >/dev/null 2>&1" 2>/dev/null; then
    if adb shell "ls $REMOTE_ERR >/dev/null 2>&1" 2>/dev/null; then
        echo "--- on-device error (StrongBox attempt) ---"
        adb shell "cat $REMOTE_ERR" | head -10
        echo "--- retrying without StrongBox ---"
        adb shell "rm -f $REMOTE_PEM $REMOTE_INFO $REMOTE_ERR" 2>/dev/null || true
        adb shell "am start -W -n $PKG/.MainActivity \
            -e challenge \"$CHALLENGE\" \
            -e alias \"$ALIAS\" \
            -e strongbox false" >/dev/null
        sleep 2
    fi
fi

if ! adb shell "ls $REMOTE_PEM >/dev/null 2>&1" 2>/dev/null; then
    echo "still no PEM produced; check device logs:"
    echo "    adb logcat -d -s EdgeTeeAttest:*"
    adb shell "ls -la $REMOTE_DIR" 2>/dev/null || true
    exit 1
fi

echo "--- pulling cert chain + info ---"
adb pull "$REMOTE_PEM" "$OUT"
adb pull "$REMOTE_INFO" "${OUT%.pem}.info"
echo "--- info ---"
cat "${OUT%.pem}.info"

echo
echo "--- running verifier with challenge binding ---"
B64_CHAL=$(printf '%s' "$CHALLENGE" | base64 -w 0)
python3 "$REPO_ROOT/tools/android_keyattest/verify.py" \
    "$OUT" --require-verified-boot --challenge "$B64_CHAL"
