#!/usr/bin/env bash
# Verify every demo contract on Basescan (Sourcify always; Etherscan if key set).
# Needs ETHERSCAN_API_KEY in ../.env for the Basescan-native green check.
#
# Registry note: each entry pins address | source file:Contract | ctor-args-abi.
# Some contracts were deployed from HISTORICAL source revisions — those carry a
# git rev; the script checks that exact blob out to a temp file to compile-match.
set -euo pipefail
cd "$(dirname "$0")/.."
export FOUNDRY_DISABLE_NIGHTLY_WARNING=1
[ -f .env ] && set -a && . ./.env && set +a
K="${ETHERSCAN_API_KEY:-}"
CHAIN=84532

# addr | repo | path:Contract | git-rev(-=working tree) | ctor-args-abi(hex, ''=none)
# NOTE per-contract compiler settings that differ from the repo default:
#   SilabsVerifier @ 0x857A… was deployed with optimizer OFF + via_ir ON
#     -> run its block with: FOUNDRY_OPTIMIZER=false FOUNDRY_VIA_IR=true
#   AndroidVerifier @ 0x78c8… is historical rev 5bc1cd3 (1-arg constructor).
INTEROP=/home/amiller/projects/tee-interop
ROOTS="0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002c1984a3ef45c1e2a918551de10603c86f7051b2249c4891cae3230eabd0c97d56d9db4ce6c5c0b293166d08986e05774a8776ceb525d9e4329520de12ba4bcc0"
SILABS_ROOT="0x00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001dbf5f0b3b3fded073c5f19289548e626adcb1f8f5346b93351c2d5775fa72153"

ENTRIES=(
  "0x1cdb41cd3F1e71d5B8a3440ab912ECD5414E0782|.|contracts/SealedBidAuction.sol:SealedBidAuction|-|"
  "0x481D2Cc69d8BaD6B8f41aeC14CA6F324F44c140c|.|contracts/TaskBoard.sol:TaskBoard|-|"
  "0x78c8c36EbAC7E2c46aF788558141d050Fb823bE8|.|contracts/AndroidKeyAttestationVerifier.sol:AndroidKeyAttestationVerifier|5bc1cd3|$ROOTS"
  "0x857A6E8810E30e63f5B544180E2F5a139d50351b|$INTEROP|contracts/SilabsVerifier.sol:SilabsVerifier|-|$SILABS_ROOT"
)

for e in "${ENTRIES[@]}"; do
  IFS='|' read -r addr repo target rev args <<<"$e"
  file="${target%%:*}"; name="${target##*:}"
  echo "=== $name @ $addr (repo $repo, rev $rev) ==="
  # SilabsVerifier needs non-default compiler flags (see NOTE above).
  if [ "$name" = "SilabsVerifier" ]; then export FOUNDRY_OPTIMIZER=false FOUNDRY_VIA_IR=true
  else unset FOUNDRY_OPTIMIZER FOUNDRY_VIA_IR; fi
  ( cd "$repo"
    restore=""
    if [ "$rev" != "-" ]; then
      cp "$file" "/tmp/.verify_bak_$$" && restore="$file"
      git show "$rev:$file" > "$file"
    fi
    argflag=(); [ -n "$args" ] && argflag=(--constructor-args "$args")
    forge verify-contract "$addr" "$target" --chain-id "$CHAIN" \
      --verifier sourcify "${argflag[@]}" 2>&1 | grep -iE "success|match|error" | tail -2 || true
    if [ -n "$K" ]; then
      forge verify-contract "$addr" "$target" --chain-id "$CHAIN" \
        --etherscan-api-key "$K" "${argflag[@]}" 2>&1 | grep -iE "guid|already|error" | tail -2 || true
    fi
    [ -n "$restore" ] && cp "/tmp/.verify_bak_$$" "$restore" && rm -f "/tmp/.verify_bak_$$"
  )
done
echo "submitted. poll: forge verify-check <guid> --chain-id $CHAIN --etherscan-api-key \$K"
