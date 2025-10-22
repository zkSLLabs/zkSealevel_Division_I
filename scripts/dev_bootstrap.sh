#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

echo "[zkSL][bootstrap] Deterministic env setup"
export TZ=UTC
export LC_ALL=C
export LANG=C
export NO_COLOR=1
export FORCE_COLOR=

require() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "[zkSL][bootstrap] missing: $1" >&2
    exit 1
  fi
}

version_gte() {
  # usage: version_gte actual required
  [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

echo "[zkSL][bootstrap] Checking toolchains"
require node
require npm
require cargo
require rustc
require solana
require anchor

NODE_VER=$(node -v | sed 's/^v//')
RUST_VER=$(rustc -V | awk '{print $2}')
SOLANA_VER=$(solana --version | awk '{print $2}')
ANCHOR_VER=$(anchor --version | awk '{print $3}')

[[ $(version_gte "$NODE_VER" "20.11.0" ) ]] || { echo "Node >= 20.11.0 required"; exit 1; }
[[ $(version_gte "$RUST_VER" "1.75.0" ) ]] || { echo "Rust >= 1.75.0 required"; exit 1; }
[[ $(version_gte "$SOLANA_VER" "1.18.0" ) ]] || { echo "Solana CLI >= 1.18.0 required"; exit 1; }
[[ $(version_gte "$ANCHOR_VER" "0.29.0" ) ]] || { echo "Anchor CLI >= 0.29.0 required"; exit 1; }

echo "[zkSL][bootstrap] Installing Node deps with frozen lockfile (if pnpm present)"
if command -v pnpm >/dev/null 2>&1; then
  pnpm install --frozen-lockfile || true
else
  npm ci || true
fi

echo "[zkSL][bootstrap] Formatting & Linting (Rust)"
if command -v cargo >/dev/null 2>&1; then
  cargo fmt --all
  cargo clippy --all-targets --all-features -- -D warnings || true
fi

echo "[zkSL][bootstrap] Building Anchor program"
anchor build

if [[ "${DEPLOY_LOCALNET:-0}" == "1" ]]; then
  echo "[zkSL][bootstrap] Deploying program to localnet"
  anchor deploy
fi

echo "[zkSL][bootstrap] Applying database migrations"
if command -v psql >/dev/null 2>&1; then
  : "${DATABASE_URL:?DATABASE_URL must be set}"
  psql "$DATABASE_URL" -f migrations/001_init.sql || true
  psql "$DATABASE_URL" -f migrations/002_indexer_state.sql || true
  psql "$DATABASE_URL" -f migrations/003_indexer_cursor.sql || true
  psql "$DATABASE_URL" -f migrations/004_indexer_last_signature.sql || true
else
  echo "[zkSL][bootstrap] psql not found; skipping migrations"
fi

if [[ ! -f .env ]]; then
  echo "[zkSL][bootstrap] Creating .env from env.example"
  cp -n env.example .env || true
fi

echo "[zkSL][bootstrap] Done."


