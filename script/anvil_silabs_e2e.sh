#!/usr/bin/env bash
# End-to-end SiLabs attestation on a local anvil chain (mimics Base):
#   install RIP-7212 P256 at 0x100 -> deploy SilabsVerifier + TEEBridge ->
#   opt into dev mode -> verify + register the LIVE SiMG301 proof.
# No fallbacks: any failed step aborts.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$PATH:$HOME/.foundry/bin" FOUNDRY_DISABLE_NIGHTLY_WARNING=1 FOUNDRY_VIA_IR=true
RPC=http://127.0.0.1:8545
PK=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80   # anvil acct0
P256=0x0000000000000000000000000000000000000100

echo "== start anvil =="
anvil --silent & ANVIL=$!; trap 'kill $ANVIL 2>/dev/null' EXIT
until cast block-number --rpc-url $RPC >/dev/null 2>&1; do sleep 0.2; done

echo "== install RIP-7212 P256 verifier at 0x100 (native on Base) =="
cast rpc --rpc-url $RPC anvil_setCode $P256 "$(forge inspect P256Verifier deployedBytecode)" >/dev/null
echo "  0x100 code bytes: $(( ($(cast code --rpc-url $RPC $P256 | wc -c) - 2) / 2 ))"

echo "== deploy + opt into dev mode + verify + register LIVE proof =="
forge script script/AnvilSilabsE2E.s.sol:AnvilSilabsE2E \
  --rpc-url $RPC --private-key $PK --broadcast --via-ir 2>&1 \
  | grep -E 'verifier|bridge|memberId|codeId|PASS|revert|Error' | sed 's/^/  /'
