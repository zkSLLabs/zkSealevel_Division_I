#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

: "${DATABASE_URL:?DATABASE_URL must be set}"
export TZ=UTC
export LC_ALL=C

echo "[zkSL][db] Applying migrations to ${DATABASE_URL}"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/001_init.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/002_indexer_state.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/003_indexer_cursor.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/004_indexer_last_signature.sql

# Schema smoke check: required tables exist
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "\\dt+ validators" >/dev/null
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "\\dt+ proofs" >/dev/null
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -c "\\dt+ indexer_state" >/dev/null

echo "[zkSL][db] Migrations applied successfully"
