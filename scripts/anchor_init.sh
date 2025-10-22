#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

export TZ=UTC
export LC_ALL=C

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[zkSL][anchor] missing: $1" >&2
    exit 1
  fi
}

require solana
require anchor

: "${RPC_URL:?RPC_URL must be set}"
: "${PROGRAM_ID_VALIDATOR_LOCK:?PROGRAM_ID_VALIDATOR_LOCK must be set}"
: "${CHAIN_ID:?CHAIN_ID must be set}"

solana config set --url "$RPC_URL" >/dev/null

# Print program id for recordkeeping
anchor keys list || true

echo "[zkSL][anchor] Program ID: ${PROGRAM_ID_VALIDATOR_LOCK}"

echo "[zkSL][anchor] Reminder: run initialize with zksl_mint, admin, aggregator_pubkey, next_aggregator_pubkey, activation_seq=${ACTIVATION_SEQ:-1}, chain_id=${CHAIN_ID}"
