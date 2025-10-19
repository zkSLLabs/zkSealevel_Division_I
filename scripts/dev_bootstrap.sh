#!/usr/bin/env bash
set -euo pipefail

# Build Anchor program and deploy to localnet
echo "[zkSL] Building Anchor program..."
if command -v anchor >/dev/null 2>&1; then
  anchor build
else
  echo "Anchor CLI not found; please install"
  exit 1
fi

echo "[zkSL] Deploying program..."
anchor deploy

echo "[zkSL] Seeding database migrations..."
if command -v psql >/dev/null 2>&1; then
  psql "$DATABASE_URL" -f migrations/001_init.sql || true
  psql "$DATABASE_URL" -f migrations/002_indexer_state.sql || true
  psql "$DATABASE_URL" -f migrations/003_indexer_cursor.sql || true
  psql "$DATABASE_URL" -f migrations/004_indexer_last_signature.sql || true
else
  echo "psql not found; skip migration"
fi

echo "[zkSL] Done."


