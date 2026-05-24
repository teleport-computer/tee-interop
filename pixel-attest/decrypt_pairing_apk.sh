#!/bin/bash
# Pixel-side decryption of a published GHA pairing bundle.
# Mirror of grab_attestation_apk.sh but for DecryptActivity.
#
# Run from this directory (tee-interop/pixel-attest/).
#
# Usage:
#   ./decrypt_pairing_apk.sh <bundle.json> <attestation.info | alias>
#
# Pass the .info file emitted by grab_attestation_apk.sh next to the .pem,
# or pass the bare alias string. The script extracts the alias either way.
#
# Writes <bundle>.decrypt_result.json next to the bundle. The plaintext
# itself never leaves the device; only its SHA-256 is reported.
set -euo pipefail

BUNDLE="${1:?path to bundle.json}"
ALIAS_SRC="${2:?attestation.info or bare alias}"

cd "$(dirname "$0")"

APK=app/build/edgetee-attest.apk
[ -f "$APK" ] || { echo "APK not built; run app/build.sh"; exit 1; }
[ -f "$BUNDLE" ] || { echo "no bundle at $BUNDLE"; exit 1; }

if [ -f "$ALIAS_SRC" ]; then
    ALIAS=$(grep -E '^alias=' "$ALIAS_SRC" | head -1 | cut -d= -f2-)
    [ -n "$ALIAS" ] || { echo "no alias= line in $ALIAS_SRC"; exit 1; }
else
    ALIAS="$ALIAS_SRC"
fi

echo "--- adb device check ---"
adb devices -l
adb get-state >/dev/null 2>&1 || { echo "no device"; exit 1; }

PKG=com.edgetee.attest
REMOTE_DIR=/sdcard/Android/data/$PKG/files
REMOTE_IN=$REMOTE_DIR/pairing_in.json
REMOTE_OUT=$REMOTE_DIR/decrypt_result.json

echo "--- ensuring APK is installed ---"
adb install -r "$APK" >/dev/null

echo "--- clearing prior decrypt output ---"
adb shell "rm -f $REMOTE_OUT" 2>/dev/null || true

echo "--- pushing bundle ---"
adb shell "mkdir -p $REMOTE_DIR" 2>/dev/null || true
adb push "$BUNDLE" "$REMOTE_IN"

echo "--- launching DecryptActivity (alias='$ALIAS') ---"
adb shell "am start -W -n $PKG/.DecryptActivity \
    -e bundle_path \"$REMOTE_IN\" \
    -e alias \"$ALIAS\"" >/dev/null
sleep 2

if ! adb shell "ls $REMOTE_OUT >/dev/null 2>&1" 2>/dev/null; then
    echo "no decrypt_result.json produced; logcat:"
    adb logcat -d -s EdgeTeeDecrypt:* | tail -20
    exit 1
fi

OUT_LOCAL="${BUNDLE%.bundle.json}.decrypt_result.json"
[ "$OUT_LOCAL" = "$BUNDLE" ] && OUT_LOCAL="${BUNDLE%.json}.decrypt_result.json"
adb pull "$REMOTE_OUT" "$OUT_LOCAL"
echo
echo "--- $OUT_LOCAL ---"
cat "$OUT_LOCAL"
echo

MATCH=$(grep -E '"match"' "$OUT_LOCAL" | head -1 | grep -oE 'true|false' || true)
if [ "$MATCH" = "true" ]; then
    echo "✔  recovered plaintext SHA-256 matches the public commitment."
else
    echo "✘  no match — see decrypt_result.json for error details."
    exit 1
fi
