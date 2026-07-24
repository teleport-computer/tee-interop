#!/usr/bin/env bash
# One command to make the live demo ready. Idempotent — run it after plugging
# in the Pixel (and any time the phone reconnects or the bridge died).
#   1. waits for the phone over adb
#   2. re-establishes the loopback forward (lost on every unplug)
#   3. starts the on-phone attest service + wakes the screen (10-min timeout)
#   4. ensures the console bridge is running on :8190
#   5. (optional) launches the notary kiosk page on the phone screen
set -euo pipefail
cd "$(dirname "$0")/../.."   # -> tee-bridge

PKG=com.edgetee.attest
echo "== waiting for phone =="
adb wait-for-device
adb devices | grep -w device | head -1

echo "== forward loopback (phone :8151) =="
adb forward tcp:8151 localabstract:edgetee >/dev/null

echo "== start attest service + wake screen =="
adb shell am start-foreground-service $PKG/.AttestService >/dev/null 2>&1 || true
adb shell input keyevent KEYCODE_WAKEUP >/dev/null 2>&1 || true
adb shell settings put system screen_off_timeout 600000 >/dev/null 2>&1 || true
sleep 1
adb shell "curl -s -m5 http://127.0.0.1:8151/state" 2>/dev/null || \
  curl -s -m5 http://127.0.0.1:8151/state || echo "  (service not answering yet — give it a few seconds)"
echo

echo "== console bridge on :8190 =="
if curl -s -m3 http://127.0.0.1:8190/api/task/list >/dev/null 2>&1; then
  echo "  already running"
else
  echo "  starting…"
  set -a; . ./.env; set +a
  nohup python3 tools/console/console_bridge.py > /tmp/console_bridge.log 2>&1 &
  sleep 3
  curl -s -m3 http://127.0.0.1:8190/api/task/list >/dev/null 2>&1 && echo "  up" || \
    { echo "  FAILED — see /tmp/console_bridge.log"; tail -5 /tmp/console_bridge.log; }
fi

echo
echo "READY."
echo "  operator console :  http://127.0.0.1:8190"
echo "  phone notary kiosk: run  $0 kiosk   (opens it on the phone screen)"
echo "  auction contract :  https://sepolia.basescan.org/address/0x37d72e359a5341bEbA37Da4D33D1de56618BE578"

if [ "${1:-}" = "kiosk" ]; then
  echo "== launching kiosk on the phone =="
  adb shell "am start -a android.intent.action.VIEW -d 'http://[::1]:8151/kiosk.html' app.vanadium.browser" >/dev/null 2>&1 \
    && echo "  kiosk opened in Vanadium on the phone" \
    || echo "  couldn't launch Vanadium — open http://[::1]:8151/kiosk.html manually"
fi
