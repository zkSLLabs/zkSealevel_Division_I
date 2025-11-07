# zkSealevel Devnet Runbook

**Complete Developer Guide for Testing on Solana Devnet**

---

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Step-by-Step Setup](#step-by-step-setup)
  - [1. Environment Setup](#1-environment-setup)
  - [2. Generate Keys](#2-generate-keys)
  - [3. Deploy Program to Devnet](#3-deploy-program-to-devnet)
  - [4. Initialize On-Chain Config](#4-initialize-on-chain-config)
  - [5. Register Validator](#5-register-validator)
  - [6. Setup Database](#6-setup-database)
  - [7. Start Services](#7-start-services)
- [Testing Workflows](#testing-workflows)
  - [End-to-End Proof Anchoring](#end-to-end-proof-anchoring)
  - [Query Proof Status](#query-proof-status)
  - [Validator Registry](#validator-registry)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)
- [Monitoring & Verification](#monitoring--verification)
- [Clean Up & Reset](#clean-up--reset)

---

## Overview

This runbook provides a complete guide for deploying and testing the zkSealevel system on Solana Devnet. The system consists of:

- **Anchor Program** (`validator_lock`): On-chain proof anchoring and validator registry
- **Orchestrator Service**: Artifact validation, DS building, and transaction submission
- **Indexer Service**: Real-time synchronization of on-chain data to PostgreSQL
- **Prover**: STARK proof generation and cryptographic signing
- **CLI**: Command-line tool for initialization and management

**Current Devnet Deployment:**
- Program ID: `BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E`
- Chain ID: `103`
- Network: Solana Devnet
- Explorer: https://explorer.solana.com/address/BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E?cluster=devnet

---

## Prerequisites

### Required Tools

1. **Node.js** (v20.x)
   ```bash
   node --version  # Should be >= 20.0.0
   ```

2. **Rust** (1.70+)
   ```bash
   rustc --version  # Should be >= 1.70.0
   ```

3. **Solana CLI** (1.17+)
   ```bash
   solana --version  # Install from: https://docs.solana.com/cli/install-solana-cli-tools
   ```

4. **Anchor CLI** (0.30.1)
   ```bash
   anchor --version  # Install: cargo install --git https://github.com/coral-xyz/anchor anchor-cli --tag v0.30.1
   ```

5. **PostgreSQL** (15+)
   ```bash
   psql --version
   # Install: https://www.postgresql.org/download/
   ```

6. **Docker** (Optional, for containerized deployment)
   ```bash
   docker --version
   ```

### System Requirements

- **OS**: Linux, macOS, or Windows (WSL2 recommended for Windows)
- **RAM**: Minimum 8GB (16GB recommended)
- **Disk**: Minimum 20GB free space
- **Network**: Stable internet connection for Devnet RPC calls

---

## Quick Start

For experienced developers who want to get up and running quickly:

```bash
# 1. Clone and install dependencies
git clone https://github.com/zkSLLabs/zkSealevel_Division_I.git
cd zkSealevel_Division_I
npm install

# 2. Configure Solana CLI for Devnet
solana config set --url https://api.devnet.solana.com

# 3. Airdrop SOL to your wallet (if needed)
solana airdrop 2

# 4. Run automated deployment (PowerShell on Windows)
npm run devnet:runbook

# 5. Initialize config (replace with your mint address)
npx tsx cli/src/main.ts init-config \
  --keypair ~/.config/solana/id.json \
  --mint <YOUR_ZKSL_MINT_ADDRESS> \
  --agg-key ./keys/aggregator.json \
  --chain-id 103

# 6. Start PostgreSQL and apply migrations
bash scripts/db_migrate.sh

# 7. Start services
npm --prefix orchestrator run build
npm --prefix indexer run build
npm --prefix orchestrator start &
npm --prefix indexer start &

# 8. Test end-to-end
npx tsx scripts/e2e_localnet.ts
```

---

## Step-by-Step Setup

### 1. Environment Setup

#### Clone the Repository

```bash
git clone https://github.com/zkSLLabs/zkSealevel_Division_I.git
cd zkSealevel_Division_I
```

#### Install Dependencies

```bash
# Install root dependencies
npm install

# Install service dependencies
npm --prefix orchestrator ci
npm --prefix indexer ci
npm --prefix cli ci
```

#### Configure Solana CLI

```bash
# Set Devnet as the cluster
solana config set --url https://api.devnet.solana.com

# Verify configuration
solana config get

# Check your wallet address
solana address

# Request airdrop (Devnet only, max 2 SOL per request)
solana airdrop 2

# Check balance
solana balance
```

### 2. Generate Keys

#### Create Keys Directory

```bash
mkdir -p keys
```

#### Generate Aggregator Key

The aggregator key is used to sign domain-separated messages for proof anchoring:

```bash
node scripts/gen_aggregator_key.js ./keys/aggregator.json
```

This creates a 64-byte Ed25519 key pair in the format:
```json
{
  "secretKey": "hex-encoded-64-bytes..."
}
```

#### Generate Solana Keypair (If Needed)

If you don't have a Solana keypair, create one:

```bash
solana-keygen new --outfile ~/.config/solana/id.json
```

**IMPORTANT**: Save your seed phrase securely! For Devnet testing, you can skip this, but for production, never lose your seed phrase.

#### Generate Fee Payer Keypair (Optional)

For production, you may want a separate fee payer:

```bash
solana-keygen new --outfile ./keys/sol_agg.json
solana airdrop 2 $(solana-keygen pubkey ./keys/sol_agg.json)
```

### 3. Deploy Program to Devnet

#### Option A: Automated Deployment (PowerShell - Windows)

```powershell
npm run devnet:runbook
```

This script will:
- Configure Solana CLI for Devnet
- Build the Anchor program
- Deploy to Devnet
- Extract the program ID
- Update `declare_id!` in the program code
- Generate aggregator key
- Create `.env` file with all configurations

#### Option B: Manual Deployment (All Platforms)

**Step 1: Prepare Cargo Lock File**

```bash
cd programs/validator_lock

# Remove existing lockfile
rm -f Cargo.lock

# Generate new lockfile with Solana toolchain
cargo +solana generate-lockfile

# Pin transitive dependencies for Solana compatibility
cargo +solana update -p proc-macro-crate@3.4.0 --precise 3.2.0
cargo +solana update -p indexmap --precise 2.11.4
cargo +solana update -p toml_edit --precise 0.22.27

cd ../..
```

**Step 2: Build Program**

```bash
anchor build --no-idl
```

**Step 3: Deploy to Devnet**

```bash
anchor deploy --provider.cluster devnet
```

**Step 4: Get Program ID**

```bash
anchor keys list
```

Look for the program ID next to `validator_lock`:
```
validator_lock: BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E
```

**Step 5: Update declare_id!**

Edit `programs/validator_lock/src/lib.rs` and update the program ID:

```rust
declare_id!("BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E");
```

**Step 6: Rebuild and Redeploy**

```bash
anchor build
anchor deploy --provider.cluster devnet
```

**Step 7: Create .env File**

Create a `.env` file in the project root:

```bash
cat > .env << 'EOF'
RPC_URL=https://api.devnet.solana.com
WS_URL=wss://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E
CHAIN_ID=103
MIN_FINALITY_COMMITMENT=finalized

AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json
FEE_PAYER_KEYPAIR_PATH=~/.config/solana/id.json
ARTIFACT_DIR=./orchestrator/data/artifacts

DATABASE_URL=postgres://postgres:postgres@localhost:5432/zksl
PORT=8080

TZ=UTC
LC_ALL=C
LANG=C
NO_COLOR=1
EOF
```

**NOTE**: Replace `PROGRAM_ID_VALIDATOR_LOCK` with your actual deployed program ID.

### 4. Initialize On-Chain Config

Before the system can anchor proofs, you must initialize the on-chain configuration PDA. This sets up the aggregator public key, chain ID, and other protocol parameters.

#### Requirements

1. A **ZKSL token mint address** (create one if you don't have it)
2. Your **payer keypair** (with SOL balance for rent + gas)
3. The **aggregator key** generated in step 2

#### Create ZKSL Token Mint (If Needed)

```bash
# Create a new token mint
spl-token create-token --decimals 9

# Example output:
# Creating token YOUR_MINT_ADDRESS
# Address:  YOUR_MINT_ADDRESS
# Decimals:  9
```

Save this mint address - you'll need it for the next step.

#### Initialize Config PDA

```bash
npx tsx cli/src/main.ts init-config \
  --keypair ~/.config/solana/id.json \
  --mint <YOUR_ZKSL_MINT_ADDRESS> \
  --agg-key ./keys/aggregator.json \
  --chain-id 103
```

**Parameters:**
- `--keypair`: Path to your Solana keypair (pays for initialization)
- `--mint`: Address of the ZKSL token mint
- `--agg-key`: Path to the aggregator key (its public key will be set as the authorized aggregator)
- `--chain-id`: Chain ID for this deployment (103 = Devnet, per protocol spec)

**Expected Output:**
```json
{
  "txid": "<TRANSACTION_SIGNATURE>"
}
```

#### Verify Config Initialization

```bash
# Query the config PDA
solana account <CONFIG_PDA_ADDRESS> --output json --url devnet
```

You can also use the Solana Explorer:
```
https://explorer.solana.com/address/<CONFIG_PDA_ADDRESS>?cluster=devnet
```

### 5. Register Validator

Validators must register before they can have proofs anchored on their behalf. Registration requires:
- ZKSL tokens (amount locked in escrow as determined by the program)
- Registration fee (paid in SOL)

#### Mint ZKSL Tokens to Your Wallet

```bash
# Create associated token account (if needed)
spl-token create-account <YOUR_ZKSL_MINT_ADDRESS>

# Mint tokens to yourself (requires mint authority)
spl-token mint <YOUR_ZKSL_MINT_ADDRESS> 10 <YOUR_WALLET_ADDRESS>
```

#### Register as Validator

```bash
npx tsx cli/src/main.ts register \
  --keypair ~/.config/solana/id.json \
  --mint <YOUR_ZKSL_MINT_ADDRESS>
```

**Expected Output:**
```json
{
  "txid": "<TRANSACTION_SIGNATURE>"
}
```

You can view the transaction on Solana Explorer:
```
https://explorer.solana.com/tx/<TRANSACTION_SIGNATURE>?cluster=devnet
```

#### Verify Registration

```bash
# Check validator PDA
solana account <VALIDATOR_PDA_ADDRESS> --output json --url devnet

# Or use the API once indexer is running:
curl http://localhost:8080/validator/<YOUR_WALLET_ADDRESS>
```

### 6. Setup Database

The indexer service requires PostgreSQL to store on-chain data.

#### Install PostgreSQL (If Not Already Installed)

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y postgresql postgresql-client
sudo systemctl start postgresql
```

**macOS:**
```bash
brew install postgresql@15
brew services start postgresql@15
```

**Windows:**
Download and install from: https://www.postgresql.org/download/windows/

#### Create Database

```bash
# Connect as postgres user
sudo -u postgres psql

# In psql shell:
CREATE DATABASE zksl;
CREATE USER postgres WITH PASSWORD 'postgres';
GRANT ALL PRIVILEGES ON DATABASE zksl TO postgres;
\q
```

#### Apply Migrations

```bash
# Make sure DATABASE_URL is set in .env
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/zksl"

# Run migrations
bash scripts/db_migrate.sh
```

**Expected Output:**
```
[zkSL][db] Applying migrations to postgres://postgres:postgres@localhost:5432/zksl
CREATE TABLE
CREATE TABLE
CREATE TABLE
CREATE TABLE
[zkSL][db] Migrations applied successfully
```

#### Verify Database Schema

```bash
psql $DATABASE_URL -c "\dt"
```

You should see tables:
- `validators`
- `proofs`
- `indexer_state`
- `indexer_cursor`

### 7. Start Services

#### Build Services

```bash
npm run build:services
```

This builds both the orchestrator and indexer TypeScript services.

#### Start Orchestrator

The orchestrator handles artifact validation, DS building, and proof anchoring.

```bash
npm --prefix orchestrator start
```

**Expected Output:**
```
orchestrator listening on :8080
```

#### Start Indexer (In a New Terminal)

The indexer synchronizes on-chain data to PostgreSQL.

```bash
npm --prefix indexer start
```

**Expected Output:**
```
[indexer] Starting at slot <CURRENT_SLOT>
[indexer] Monitoring account: <CONFIG_PDA>
[indexer] Monitoring account: <AGGREGATOR_PDA>
```

#### Verify Services are Running

```bash
# Check orchestrator health
curl http://localhost:8080/health

# Expected: {"status":"ok","version":"0.1.0"}
```

---

## Testing Workflows

### End-to-End Proof Anchoring

This workflow demonstrates the complete lifecycle: artifact creation → proof anchoring → status query.

#### Using the E2E Script

```bash
# Set orchestrator URL (default: http://localhost:8080)
export ORCH_URL=http://localhost:8080

# Run end-to-end test
npx tsx scripts/e2e_localnet.ts
```

**Expected Output:**
```json
{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "proof_hash": "abc123..."
}
{
  "aggregator_signature": "def456...",
  "ds_hash": "789ghi...",
  "transaction_id": "https://explorer.solana.com/tx/..."
}
```

#### Manual API Testing

**Step 1: Create Artifact**

```bash
curl -X POST http://localhost:8080/artifact \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "start_slot": 1,
    "end_slot": 64,
    "state_root_before": "0000000000000000000000000000000000000000000000000000000000000000",
    "state_root_after": "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  }'
```

**Response:**
```json
{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "proof_hash": "abc123def456..."
}
```

**Step 2: Anchor Proof On-Chain**

```bash
curl -X POST http://localhost:8080/anchor \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: $(uuidgen)" \
  -d '{
    "artifact_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Response:**
```json
{
  "aggregator_signature": "8f3a2...",
  "ds_hash": "6b7c1...",
  "transaction_id": "2ZE7Rx..."
}
```

**Step 3: Query Proof Status**

```bash
curl http://localhost:8080/proof/550e8400-e29b-41d4-a716-446655440000
```

**Response:**
```json
{
  "artifact": {
    "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
    "start_slot": 1,
    "end_slot": 64,
    "state_root_before": "00...00",
    "state_root_after": "ff...ff"
  },
  "status": {
    "commitment_level": "finalized",
    "txid": "2ZE7Rx...",
    "seq": 1
  }
}
```

### Query Proof Status

Check the status of a previously anchored proof:

```bash
curl http://localhost:8080/proof/<ARTIFACT_ID>
```

The `commitment_level` field shows the transaction finality:
- `processed`: Transaction included in a block
- `confirmed`: ~66% certainty (optimistic confirmation)
- `finalized`: ~100% certainty (32 confirmed blocks)

### Validator Registry

#### List All Validators

Query via database:
```bash
psql $DATABASE_URL -c "SELECT * FROM validators;"
```

#### Query Specific Validator

```bash
curl http://localhost:8080/validator/<VALIDATOR_PUBKEY>
```

**Response:**
```json
{
  "validator": {
    "pubkey": "H6A...",
    "registered_at": "2024-11-07T12:00:00Z",
    "zksl_locked": "1000000000",
    "is_active": true
  }
}
```

---

## API Reference

### Orchestrator API

**Base URL:** `http://localhost:8080`

#### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

#### `POST /artifact`

Create and persist a canonical artifact.

**Headers:**
- `Content-Type: application/json`
- `Idempotency-Key: <uuid>` (required)

**Request Body:**
```json
{
  "start_slot": 1,
  "end_slot": 64,
  "state_root_before": "0000...0000",  // 64-char hex (32 bytes)
  "state_root_after": "ffff...ffff"     // 64-char hex (32 bytes)
}
```

**Response:**
```json
{
  "artifact_id": "<uuid-v4>",
  "proof_hash": "<32-byte-hex>"
}
```

**Constraints:**
- `start_slot` ≤ `end_slot`
- Slot window ≤ 2048 slots
- Artifact size ≤ 512KB
- State roots must be valid 32-byte hex strings

#### `POST /anchor`

Anchor a proof on-chain.

**Headers:**
- `Content-Type: application/json`
- `Idempotency-Key: <uuid>` (required)

**Request Body:**
```json
{
  "artifact_id": "<uuid-v4>"
}
```

**Response:**
```json
{
  "aggregator_signature": "<64-byte-hex>",
  "ds_hash": "<32-byte-hex>",
  "transaction_id": "<signature>"
}
```

**Errors:**
- `404 Not Found`: Artifact doesn't exist
- `400 ChainIdMismatch`: On-chain CHAIN_ID doesn't match env
- `400 AggregatorKeyMismatch`: Aggregator key not authorized for this seq

#### `GET /proof/:artifact_id`

Query proof status.

**Response:**
```json
{
  "artifact": {
    "artifact_id": "<uuid>",
    "start_slot": 1,
    "end_slot": 64,
    "state_root_before": "...",
    "state_root_after": "..."
  },
  "status": {
    "commitment_level": "finalized",
    "txid": "<signature>",
    "seq": 1
  }
}
```

#### `GET /validator/:pubkey`

Query validator registration status.

**Response:**
```json
{
  "validator": {
    "pubkey": "<base58>",
    "registered_at": "<timestamp>",
    "zksl_locked": "1000000000",
    "is_active": true
  }
}
```

---

## Troubleshooting

### Common Issues

#### 1. "Aggregator key not found"

**Error:**
```
[conformance] Aggregator key not found at ./keys/aggregator.json
```

**Solution:**
```bash
node scripts/gen_aggregator_key.js ./keys/aggregator.json
```

#### 2. "DATABASE_URL must be set"

**Error:**
```
scripts/db_migrate.sh: line 5: DATABASE_URL: DATABASE_URL must be set
```

**Solution:**
```bash
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/zksl"
```

Or add to `.env` file.

#### 3. "Program ID mismatch"

**Error:**
```
Error: ProgramId mismatch
```

**Solution:**
Ensure the program ID in your `.env` matches the deployed program:
```bash
anchor keys list
# Update PROGRAM_ID_VALIDATOR_LOCK in .env
```

#### 4. "Insufficient SOL balance"

**Error:**
```
Error: Attempt to debit an account but found no record of a prior credit
```

**Solution:**
```bash
solana airdrop 2
solana balance
```

#### 5. "Port 8080 already in use"

**Error:**
```
Error: listen EADDRINUSE: address already in use :::8080
```

**Solution:**
```bash
# Find and kill the process
lsof -ti:8080 | xargs kill -9

# Or use a different port
PORT=3000 npm --prefix orchestrator start
```

#### 6. "Failed to connect to database"

**Error:**
```
Error: connect ECONNREFUSED 127.0.0.1:5432
```

**Solution:**
```bash
# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql@15  # macOS

# Verify it's running
psql -U postgres -c "SELECT 1"
```

#### 7. "STARK proof verification failed"

If you have `REQUIRE_STARK=1` in your environment:

**Error:**
```
Error: StarkVerifyFailed
```

**Solution:**
For Devnet testing, you can disable STARK requirement:
```bash
unset REQUIRE_STARK
# Or in .env: remove or comment out REQUIRE_STARK=1
```

### Debug Mode

Enable verbose logging:

```bash
# Orchestrator
DEBUG=* npm --prefix orchestrator start

# Indexer
DEBUG=* npm --prefix indexer start
```

### Check Logs

```bash
# Orchestrator logs
npm --prefix orchestrator start 2>&1 | tee orchestrator.log

# Indexer logs
npm --prefix indexer start 2>&1 | tee indexer.log

# Solana program logs
solana logs BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E --url devnet
```

---

## Monitoring & Verification

### On-Chain Verification

#### View Program on Solana Explorer

```
https://explorer.solana.com/address/BCx5eHewBbe6Ft2xXpDXTghuiy5WxM636xN5G45KCp5E?cluster=devnet
```

#### View Transaction

```
https://explorer.solana.com/tx/<TRANSACTION_SIGNATURE>?cluster=devnet
```

#### Query Account Data

```bash
# Config PDA
solana account <CONFIG_PDA> --url devnet

# Aggregator state PDA
solana account <AGGREGATOR_PDA> --url devnet

# Proof record PDA
solana account <PROOF_PDA> --url devnet
```

### Database Queries

#### View All Proofs

```bash
psql $DATABASE_URL -c "SELECT * FROM proofs ORDER BY ts DESC LIMIT 10;"
```

#### View Validators

```bash
psql $DATABASE_URL -c "SELECT * FROM validators;"
```

#### Check Indexer State

```bash
psql $DATABASE_URL -c "SELECT * FROM indexer_state;"
```

### Performance Metrics

#### RPC Rate Limiting

Devnet has rate limits. Monitor your usage:

```bash
# Use a custom RPC endpoint for higher limits
export RPC_URL=https://your-custom-rpc-endpoint.com
```

#### Transaction Confirmation Time

Typical times on Devnet (may vary based on network conditions):
- **Processed**: Sub-second
- **Confirmed**: Several seconds
- **Finalized**: 30+ seconds (requires 32 confirmed blocks)

---

## Clean Up & Reset

### Reset Local State

```bash
# Stop services
pkill -f orchestrator
pkill -f indexer

# Clear artifacts
rm -rf orchestrator/data/artifacts/*

# Reset database
psql $DATABASE_URL -c "DROP TABLE IF EXISTS validators, proofs, indexer_state, indexer_cursor CASCADE;"
bash scripts/db_migrate.sh
```

### Redeploy Program

```bash
# Build and deploy
anchor build
anchor deploy --provider.cluster devnet

# Update program ID
anchor keys list
# Update declare_id! in programs/validator_lock/src/lib.rs
# Update PROGRAM_ID_VALIDATOR_LOCK in .env

# Rebuild
anchor build
anchor deploy --provider.cluster devnet
```

### Generate New Keys

```bash
# Backup old keys
mv keys keys.backup

# Generate new
mkdir keys
node scripts/gen_aggregator_key.js ./keys/aggregator.json
solana-keygen new --outfile ./keys/sol_agg.json
```

---

## Additional Resources

### Documentation

- [Technical Specification](./TECHNICAL_SPECIFICATION.md)
- [README](./README.md)
- [Anchor Documentation](https://www.anchor-lang.com)
- [Solana Documentation](https://docs.solana.com)

### Scripts

- `scripts/e2e_localnet.ts` - End-to-end testing
- `scripts/devnet_runbook.ps1` - Automated deployment (PowerShell)
- `scripts/gen_aggregator_key.js` - Key generation
- `scripts/db_migrate.sh` - Database migrations
- `scripts/conformance.js` - Conformance testing (Node ↔ Rust)

### Support

- GitHub Issues: https://github.com/zkSLLabs/zkSealevel_Division_I/issues
- Solana Discord: https://discord.gg/solana

---

## Appendix

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RPC_URL` | Yes | `https://api.devnet.solana.com` | Solana RPC endpoint |
| `WS_URL` | Yes | `wss://api.devnet.solana.com` | WebSocket endpoint |
| `PROGRAM_ID_VALIDATOR_LOCK` | Yes | - | Deployed program ID |
| `CHAIN_ID` | Yes | `103` | Chain identifier (103=Devnet) |
| `AGGREGATOR_KEYPAIR_PATH` | Yes | `./keys/aggregator.json` | Aggregator signing key |
| `FEE_PAYER_KEYPAIR_PATH` | No | `~/.config/solana/id.json` | Transaction fee payer |
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `PORT` | No | `8080` | Orchestrator HTTP port |
| `MIN_FINALITY_COMMITMENT` | No | `finalized` | Minimum commitment level |
| `ARTIFACT_DIR` | No | `./orchestrator/data/artifacts` | Artifact storage path |
| `REQUIRE_STARK` | No | - | Enable STARK proof verification |

### PDA Derivation Reference

All PDAs use the program ID as the base with specific seeds:

```
Config PDA:          ["zksl", "config"]
Aggregator PDA:      ["zksl", "aggregator"]
Range State PDA:     ["zksl", "range"]
Proof Record PDA:    ["zksl", "proof", <proof_hash:32>, <seq:8>]
Validator PDA:       ["zksl", "validator", <validator_pubkey:32>]
```

### Network Endpoints

**Devnet:**
- RPC: `https://api.devnet.solana.com`
- WebSocket: `wss://api.devnet.solana.com`
- Explorer: `https://explorer.solana.com/?cluster=devnet`

**Testnet (Future):**
- RPC: `https://api.testnet.solana.com`
- WebSocket: `wss://api.testnet.solana.com`

**Mainnet Beta (Production):**
- RPC: `https://api.mainnet-beta.solana.com`
- WebSocket: `wss://api.mainnet-beta.solana.com`

---

**Version:** 0.1.0  
**Maintained by:** zkSL Labs
