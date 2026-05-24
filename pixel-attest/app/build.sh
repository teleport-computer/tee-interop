#!/bin/bash
# Manual APK build: javac -> d8 -> aapt2 link -> zipalign -> apksigner sign
# No gradle / no Android Studio needed.
#
# Requires ANDROID_HOME pointing at an Android SDK install with:
#   platforms/android-34/android.jar
#   build-tools/34.0.0/{aapt2,d8,zipalign,apksigner}
#
# Install via sdkmanager:
#   sdkmanager "platforms;android-34" "build-tools;34.0.0"
set -euo pipefail

cd "$(dirname "$0")"

if [ -z "${ANDROID_HOME:-}" ]; then
    echo "ANDROID_HOME not set. Point it at an Android SDK install (Android Studio's default is ~/Android/Sdk)."
    exit 1
fi

PLATFORM="$ANDROID_HOME/platforms/android-34/android.jar"
BT="$ANDROID_HOME/build-tools/34.0.0"
[ -f "$PLATFORM" ] || { echo "missing $PLATFORM (install via sdkmanager 'platforms;android-34')"; exit 1; }
[ -x "$BT/aapt2" ] || { echo "missing $BT/aapt2 (install via sdkmanager 'build-tools;34.0.0')"; exit 1; }

rm -rf build
mkdir -p build/classes build/dex

echo "--- javac ---"
javac -source 11 -target 11 \
      -d build/classes \
      -cp "$PLATFORM" \
      src/com/edgetee/attest/*.java

echo "--- d8 ---"
"$BT/d8" --lib "$PLATFORM" \
         --output build/dex \
         build/classes/com/edgetee/attest/*.class

echo "--- aapt2 link (manifest only, no resources) ---"
"$BT/aapt2" link -o build/unsigned.apk \
            -I "$PLATFORM" \
            --manifest AndroidManifest.xml \
            --target-sdk-version 34 \
            --min-sdk-version 28

echo "--- add classes.dex into the APK ---"
( cd build/dex && zip -j ../unsigned.apk classes.dex )

echo "--- zipalign ---"
"$BT/zipalign" -f -p 4 build/unsigned.apk build/aligned.apk

echo "--- create debug keystore if missing ---"
KS=build/debug.keystore
if [ ! -f "$KS" ]; then
  keytool -genkey -v -keystore "$KS" -storepass android -alias androiddebugkey \
          -keypass android -keyalg RSA -keysize 2048 -validity 10000 \
          -dname "CN=Android Debug,O=Android,C=US"
fi

echo "--- apksigner sign ---"
"$BT/apksigner" sign --ks "$KS" --ks-pass pass:android --key-pass pass:android \
                --ks-key-alias androiddebugkey \
                --out build/edgetee-attest.apk \
                build/aligned.apk

echo
echo "OK: build/edgetee-attest.apk  ($(stat -c%s build/edgetee-attest.apk) bytes)"
"$BT/apksigner" verify --print-certs build/edgetee-attest.apk | head -10
