#!/usr/bin/env bash
set -euo pipefail

# Devnet North Star Route end-to-end bring-up
# - Builds services and prover (with STARK)
# - Deploys validator_lock_v2 via Anchor
# - Writes .env with USE_V2=1 and REQUIRE_STARK=1
# - Generates aggregator key
# - Applies DB migrations (including v2)
# - Starts orchestrator and indexer
# - Runs a sample /prove and /anchor flow

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "==> Building services"
npm run build:services
cargo build --release --manifest-path prover/Cargo.toml --features stark

echo "==> Deploying validator_lock_v2 (devnet)"
anchor build
anchor deploy --provider.cluster devnet --program-name validator_lock_v2
PROG_ID=$(anchor keys list | awk '/validator_lock_v2:/ {print $2}')
if [[ -z "$PROG_ID" ]]; then
  echo "FATAL: Could not parse validator_lock_v2 program id"
  exit 1
fi
echo "Program ID (v2): $PROG_ID"

echo "==> Writing .env (devnet, USE_V2=1)"
cat > .env <<EOF
RPC_URL=https://api.devnet.solana.com
WS_URL=wss://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=${PROG_ID}
CHAIN_ID=103
MIN_FINALITY_COMMITMENT=finalized
REQUIRE_STARK=1
USE_V2=1

ARTIFACT_DIR=./orchestrator/data/artifacts
AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json
FEE_PAYER_KEYPAIR_PATH=\$HOME/.config/solana/id.json

PORT=8080
DATABASE_URL=postgres://postgres:postgres@localhost:5432/zksl
TZ=UTC
EOF

echo "==> Generating aggregator key"
mkdir -p keys
node scripts/gen_aggregator_key.js keys/aggregator.json

echo "==> Applying DB migrations (incl. v2)"
psql "\${DATABASE_URL}" < migrations/001_init.sql || true
psql "\${DATABASE_URL}" < migrations/002_indexer_state.sql || true
psql "\${DATABASE_URL}" < migrations/003_indexer_cursor.sql || true
psql "\${DATABASE_URL}" < migrations/004_indexer_last_signature.sql || true
psql "\${DATABASE_URL}" < migrations/005_proofs_v2_stark.sql || true

echo "==> Initializing on-chain state"
npx tsx cli/src/main.ts init-config \
  --keypair "\$HOME/.config/solana/id.json" \
  --mint <YOUR_ZKSL_MINT_PUBKEY> \
  --agg-key keys/aggregator.json \
  --chain-id 103

npx tsx cli/src/main.ts init-state \
  --keypair "\$HOME/.config/solana/id.json"

echo "==> Start orchestrator and indexer in terminals or background"
echo "npm --prefix orchestrator run build && node orchestrator/dist/src/server.js &"
echo "npm --prefix indexer run build && node indexer/dist/src/index.js &"

echo "==> Sample /prove and /anchor"
echo "curl -X POST http://localhost:8080/prove -H 'Idempotency-Key: nsr-1' -H 'Content-Type: application/json' -d '{\"start_slot\":1,\"end_slot\":2,\"state_root_before\":\"$(printf %064d 0)\",\"state_root_after\":\"$(printf %064d 0)\"}'"
echo "curl -X POST http://localhost:8080/anchor -H 'Idempotency-Key: nsr-2' -H 'Content-Type: application/json' -d '{\"artifact_id\":\"<ARTIFACT_ID_FROM_PROVE>\"}'"

echo "Done."


