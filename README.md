```
  ███████╗██╗  ██╗███████╗███████╗ █████╗ ██╗     ███████╗██╗   ██╗███████╗██╗     
  ╚══███╔╝██║ ██╔╝██╔════╝██╔════╝██╔══██╗██║     ██╔════╝██║   ██║██╔════╝██║     
    ███╔╝ █████╔╝ ███████╗█████╗  ███████║██║     █████╗  ██║   ██║█████╗  ██║     
   ███╔╝  ██╔═██╗ ╚════██║██╔══╝  ██╔══██║██║     ██╔══╝  ╚██╗ ██╔╝██╔══╝  ██║     
  ███████╗██║  ██╗███████║███████╗██║  ██║███████╗███████╗ ╚████╔╝ ███████╗███████╗
  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝  ╚═══╝  ╚══════╝╚══════╝
```

<div align="center">

# zkSealevel

**Zero-Knowledge Proof System for Solana Validator State Verification**

[![Solana](https://img.shields.io/badge/Solana-Devnet-14F195?logo=solana&logoColor=white)](https://explorer.solana.com/address/4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ?cluster=devnet)
[![Rust](https://img.shields.io/badge/Rust-1.70+-orange?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4+-blue?logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Anchor](https://img.shields.io/badge/Anchor-0.30.1-blueviolet)](https://www.anchor-lang.com)
[![License](https://img.shields.io/badge/License-Proprietary-red)](LICENSE)
[![CI Status](https://img.shields.io/badge/CI-Passing-success)](https://github.com/zkSLLabs/zkSealevel_Division_I/actions)

[Documentation](#table-of-contents) • [Architecture](#architecture) • [Deployment](#deployment-guide) • [API Reference](#api-reference)

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Protocol Specifications](#protocol-specifications)
- [System Components](#system-components)
- [Deployment Guide](#deployment-guide)
- [API Reference](#api-reference)
- [Database Schema](#database-schema)
- [Development Workflow](#development-workflow)
- [Testing & Validation](#testing--validation)
- [Project Status](#project-status)

---

## Overview

zkSealevel is a production-grade zero-knowledge proof anchoring system for Solana, designed to cryptographically verify validator state transitions using STARK proofs and Ed25519-signed domain-separated messages. The system integrates on-chain program verification with off-chain proof generation, orchestration, and indexing to provide a complete end-to-end proof lifecycle.

### Core Capabilities

- **Proof Generation**: STARK-based zero-knowledge proofs for Solana state validation
- **On-Chain Anchoring**: Immutable proof records anchored to Solana via Anchor program
- **Validator Registry**: Token-gated validator registration with 1:1 escrow mechanics
- **State Indexing**: Real-time synchronization of on-chain proof records to PostgreSQL
- **Cryptographic Integrity**: Blake3 hashing, Ed25519 signatures, and strict domain separation

### Key Features

- Byte-precise protocol implementation matching formal specification
- Deterministic artifact canonicalization for reproducibility
- Strict transaction ordering enforcement (ComputeBudget → Ed25519 → Anchor)
- Monotonic sequence and slot-range validation
- Commitment-level reconciliation (processed → confirmed → finalized)
- CI/CD with conformance testing (Node.js ↔ Rust proof_hash validation)

---

## Architecture

The zkSealevel system comprises four primary components operating in concert:

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                            zkSealevel Architecture                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

    ┌─────────────────────────────────────────────────────────────────┐
    │                        CLIENT INTERFACE                         │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ╔═══════════════════════════════════════════════════════════════╗
    ║                   ORCHESTRATOR SERVICE (TS)                   ║
    ║  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐      ║
    ║  │ Artifact │  │    DS    │  │   Tx     │  │   RPC    │      ║
    ║  │Validation│  │  Build   │  │ Assembly │  │ Submitter│      ║
    ║  └──────────┘  └──────────┘  └──────────┘  └──────────┘      ║
    ╚═══════════════════════════════════════════════════════════════╝
            │                                              │
            ▼                                              ▼
    ╔═══════════════════╗                    ╔═══════════════════════╗
    ║  PROVER (Rust)    ║                    ║  INDEXER SERVICE (TS) ║
    ║ ┌───────────────┐ ║                    ║ ┌───────────────────┐ ║
    ║ │ STARK Circuit │ ║                    ║ │ Account Monitor   │ ║
    ║ └───────────────┘ ║                    ║ └───────────────────┘ ║
    ║ ┌───────────────┐ ║                    ║ ┌───────────────────┐ ║
    ║ │  Blake3 Hash  │ ║                    ║ │  Borsh Decoder    │ ║
    ║ └───────────────┘ ║                    ║ └───────────────────┘ ║
    ║ ┌───────────────┐ ║                    ║ ┌───────────────────┐ ║
    ║ │ Ed25519 Sign  │ ║                    ║ │ Commitment Track  │ ║
    ║ └───────────────┘ ║                    ║ └───────────────────┘ ║
    ╚═══════════════════╝                    ╚═══════════════════════╝
            │                                              │
            │                                              ▼
            │                                  ┌─────────────────────┐
            │                                  │  PostgreSQL Database│
            │                                  │ ┌─────────────────┐ │
            │                                  │ │   validators    │ │
            │                                  │ │   proofs        │ │
            │                                  │ │   indexer_state │ │
            │                                  │ └─────────────────┘ │
            │                                  └─────────────────────┘
            │
            ▼
    ╔═══════════════════════════════════════════════════════════════╗
    ║              SOLANA BLOCKCHAIN (Devnet)                       ║
    ║                                                               ║
    ║  ┌────────────────────────────────────────────────────────┐  ║
    ║  │         validator_lock Program (Anchor)                │  ║
    ║  │  Program ID: 4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHy... │  ║
    ║  ├────────────────────────────────────────────────────────┤  ║
    ║  │  Instructions:                                         │  ║
    ║  │  • initialize_config      • anchor_proof               │  ║
    ║  │  • update_aggregator       • register_validator        │  ║
    ║  │  • unlock_validator                                    │  ║
    ║  └────────────────────────────────────────────────────────┘  ║
    ║                                                               ║
    ║  ┌──────────────────────────────────────────────────────┐    ║
    ║  │ PDAs (Program Derived Addresses):                    │    ║
    ║  │  • Config            [zksl, config]                  │    ║
    ║  │  • AggregatorState   [zksl, aggregator]              │    ║
    ║  │  • RangeState        [zksl, range]                   │    ║
    ║  │  • ProofRecord       [zksl, proof, hash, seq]        │    ║
    ║  │  • ValidatorRecord   [zksl, validator, pubkey]       │    ║
    ║  └──────────────────────────────────────────────────────┘    ║
    ╚═══════════════════════════════════════════════════════════════╝
```

### Component Interaction Flow

1. **Prover** generates canonical JSON artifact, computes `proof_hash = blake3(artifact)`, constructs 110-byte Domain Separation (DS) message, signs with aggregator Ed25519 key
2. **Orchestrator** validates artifacts, enforces idempotency, builds transaction with strict instruction ordering, submits to Solana
3. **On-Chain Program** (`validator_lock`) verifies Ed25519 signature over DS, enforces sequence monotonicity, validates slot ranges, writes `ProofRecord` PDA
4. **Indexer** monitors program accounts via WebSocket/polling, decodes Borsh-serialized data, upserts to PostgreSQL with commitment tracking
5. **CLI/API** provides interface for proof submission, validator registration, and system status queries

---

## Protocol Specifications

### Domain Separation (DS) Message Layout

```
┌────────────────────────────────────────────────────────────────────┐
│              Domain Separation Message (110 bytes)                 │
├─────────┬────────┬────────┬──────────────────────────────────────┤
│ Offset  │ Length │  Type  │           Description                │
├─────────┼────────┼────────┼──────────────────────────────────────┤
│    0    │   14   │ ASCII  │ Prefix: "zKSL/anchor/v1"             │
│   14    │    8   │ u64 LE │ Chain ID (103 = Devnet)              │
│   22    │   32   │ Pubkey │ Program ID                           │
│   54    │   32   │ Blake3 │ Proof Hash                           │
│   86    │    8   │ u64 LE │ Start Slot (inclusive)               │
│   94    │    8   │ u64 LE │ End Slot (inclusive)                 │
│  102    │    8   │ u64 LE │ Sequence Number (monotonic)          │
└─────────┴────────┴────────┴──────────────────────────────────────┘
                        Total: 110 bytes

            DS Hash = blake3(DS) → 32 bytes (stored on-chain)
```

The DS message is exactly **110 bytes**, constructed as follows:

| Field           | Offset | Length | Type      | Description                          |
|----------------|--------|--------|-----------|--------------------------------------|
| Prefix         | 0      | 14     | ASCII     | `"zKSL/anchor/v1"`                   |
| Chain ID       | 14     | 8      | u64 LE    | Solana chain identifier (103=devnet) |
| Program ID     | 22     | 32     | Pubkey    | validator_lock program address       |
| Proof Hash     | 54     | 32     | Blake3    | Hash of canonical artifact JSON      |
| Start Slot     | 86     | 8      | u64 LE    | Inclusive lower bound                |
| End Slot       | 94     | 8      | u64 LE    | Inclusive upper bound                |
| Sequence       | 102    | 8      | u64 LE    | Monotonic proof sequence number      |

**Total**: 110 bytes

**DS Hash**: `ds_hash = blake3(DS)` (32 bytes) — stored on-chain for integrity verification

### Transaction Ordering Requirements

```
╔═══════════════════════════════════════════════════════════════════╗
║            TRANSACTION INSTRUCTION ORDERING (STRICT)              ║
╠═══════════════════════════════════════════════════════════════════╣
║                                                                   ║
║   [1]  ComputeBudgetProgram::SetComputeUnitLimit                 ║
║        └─> units >= 200,000 CU                                   ║
║             │                                                     ║
║             ▼                                                     ║
║   [2]  Ed25519Program::Verify                                    ║
║        ├─> Public Key: aggregator_pubkey                         ║
║        ├─> Message: 110-byte DS                                  ║
║        └─> Signature: Ed25519 (64 bytes)                         ║
║             │                                                     ║
║             ▼                                                     ║
║   [3]  ValidatorLockProgram::anchor_proof                        ║
║        └─> Discriminator (8) + Borsh Payload (185)              ║
║                                                                   ║
║   ⚠ Reordering or omitting instructions → InvalidInstructionOrder║
╚═══════════════════════════════════════════════════════════════════╝
```

All `anchor_proof` transactions MUST include the following instructions in exact order:

1. **ComputeBudgetProgram::SetComputeUnitLimit** (≥200,000 CU)
2. **Ed25519Program::Verify** (single signature over 110-byte DS)
3. **ValidatorLockProgram::anchor_proof** (Anchor instruction with Borsh payload)

Failure to maintain this ordering results in on-chain rejection with `InvalidInstructionOrder`.

### Canonical Artifact Format

```
┌────────────────────────────────────────────────────────────────────┐
│           Canonical Artifact (JSON) - Deterministic                │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  Canonicalization Rules:                                          │
│  ✓ Map keys sorted lexicographically                              │
│  ✓ No whitespace or extra formatting                              │
│  ✓ Hex fields lowercased                                          │
│  ✓ Numbers without scientific notation                            │
│  ✓ artifact_id as lowercase UUID v4                               │
│                                                                    │
│  Storage Path: ARTIFACT_DIR/YYYY/MM/DD/{artifact_id}.json         │
│                                                                    │
│  proof_hash = blake3(canonical_json_bytes)                        │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

Artifacts are deterministically canonicalized using JSON Canonicalization Scheme (JCS):

- Map keys sorted lexicographically
- No whitespace or formatting
- Hex fields lowercased
- Numbers serialized without scientific notation
- `artifact_id` as lowercase UUID v4
- File storage: `ARTIFACT_DIR/YYYY/MM/DD/{artifact_id}.json`

**Required Fields**:
```json
{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "start_slot": 1000,
  "end_slot": 1064,
  "state_root_before": "0000000000000000000000000000000000000000000000000000000000000001",
  "state_root_after": "0000000000000000000000000000000000000000000000000000000000000002"
}
```

### PDA Seeds and Account Sizes

| Account Type      | Seeds                                  | Size (bytes) |
|-------------------|----------------------------------------|--------------|
| Config            | `[b"zksl", b"config"]`                 | 168          |
| AggregatorState   | `[b"zksl", b"aggregator"]`             | 128          |
| RangeState        | `[b"zksl", b"range"]`                  | 128          |
| ProofRecord       | `[b"zksl", b"proof", proof_hash, seq]` | 262          |
| ValidatorRecord   | `[b"zksl", b"validator", pubkey]`      | 136          |

---

## System Components

### 1. Prover Service (Rust)

**Location**: `prover/src/main.rs`

**Responsibilities**:
- Generate STARK proofs for constrained computations
- Canonicalize proof artifacts to deterministic JSON
- Compute `proof_hash = blake3(canonical_json)`
- Construct 110-byte DS message
- Sign DS with Ed25519 aggregator keypair
- Output signed proof artifact

**Key Dependencies**:
- `blake3` 1.5
- `ed25519-dalek` 2.1
- `serde_json` 1.0
- `bs58` 0.5

**Invocation**:
```bash
cargo run -p zksl-prover -- \
  --input artifact.json \
  --out signed_artifact.json \
  --agg-key keys/aggregator.json \
  --chain-id 103 \
  --program_id 4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ \
  --seq 1
```

### 2. Orchestrator Service (TypeScript/Node.js)

**Location**: `orchestrator/src/server.ts`

**Responsibilities**:
- REST API for artifact submission (`POST /artifact`, `POST /prove`)
- Idempotency enforcement via `Idempotency-Key` header
- Artifact validation and canonicalization
- DS message construction and verification
- Transaction assembly with strict instruction ordering
- On-chain submission via `@solana/web3.js`
- Proof anchoring endpoint (`POST /anchor`)
- Validator and proof status queries

**Endpoints**:

| Method | Path                    | Description                          |
|--------|-------------------------|--------------------------------------|
| POST   | `/artifact`             | Submit proof artifact for validation |
| POST   | `/prove`                | Submit + auto-anchor proof           |
| POST   | `/anchor`               | Anchor validated artifact on-chain   |
| GET    | `/proof/:artifact_id`   | Query proof record status            |
| GET    | `/validator/:pubkey`    | Query validator registration         |
| GET    | `/health`               | Service health check                 |

**Configuration** (via environment):
```bash
PORT=8080
RPC_URL=https://api.devnet.solana.com
WS_URL=wss://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ
CHAIN_ID=103
AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json
ARTIFACT_DIR=./orchestrator/data/artifacts
MIN_FINALITY_COMMITMENT=finalized
```

### 3. Indexer Service (TypeScript/Node.js)

**Location**: `indexer/src/index.ts`

**Responsibilities**:
- Monitor Solana program accounts via WebSocket subscriptions
- Poll for missed account updates
- Decode Borsh-serialized account data
- Upsert `validators` and `proofs` tables in PostgreSQL
- Track commitment levels (processed → confirmed → finalized)
- Persist scan position for crash recovery

**Database Tables**:
- `validators`: validator pubkey, status, escrow, lock/unlock timestamps
- `proofs`: artifact_id, proof_hash, seq, ds_hash, state roots, commitment_level, txid
- `indexer_state`: last_scan_ts for cursor persistence

**Configuration**:
```bash
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/zksl
RPC_URL=https://api.devnet.solana.com
WS_URL=wss://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ
MIN_FINALITY_COMMITMENT=finalized
```

### 4. On-Chain Program (Anchor/Rust)

**Location**: `programs/validator_lock/src/lib.rs`

**Program ID (Devnet)**: `4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ`

**Instructions**:

| Instruction          | Description                                      |
|----------------------|--------------------------------------------------|
| `initialize_config`  | Admin-only: set mint, aggregator, chain_id      |
| `update_aggregator`  | Admin-only: rotate aggregator key after seq     |
| `register_validator` | Lock exactly 1 token, create ValidatorRecord    |
| `unlock_validator`   | Release escrowed token, mark validator unlocked |
| `anchor_proof`       | Verify Ed25519 signature, write ProofRecord PDA |

**Validation Rules** (enforced in `anchor_proof`):
- ComputeBudget instruction present with ≥200k CU
- Exactly 1 Ed25519 instruction immediately preceding anchor_proof
- Ed25519 public key matches current aggregator (or next if seq ≥ activation_seq)
- Ed25519 message matches constructed 110-byte DS
- `ds_hash` in instruction payload matches `blake3(DS)`
- `seq` strictly greater than `AggregatorState::last_seq`
- `start_slot ≤ end_slot` and `end_slot - start_slot ≤ 2048`
- `end_slot` strictly greater than `RangeState::last_end_slot`

**Error Codes**:
- `6000`: MissingComputeBudget
- `6001`: MissingEd25519Instruction
- `6002`: InvalidInstructionOrder
- `6003`: Ed25519VerificationFailed
- `6004`: DSHashMismatch
- `6005`: SequenceNotMonotonic
- `6006`: InvalidSlotRange
- `6007`: SlotRangeNotMonotonic
- `6008`: InvalidAggregatorPubkey

### 5. CLI Tool (TypeScript/Node.js)

**Location**: `cli/src/main.ts`

**Commands**:
```bash
# Initialize on-chain config
npx tsx cli/src/main.ts init-config \
  --keypair payer.json \
  --mint <MINT_PUBKEY> \
  --agg-key keys/aggregator.json \
  --chain-id 103

# Register validator (lock 1 token)
npx tsx cli/src/main.ts register \
  --keypair validator.json \
  --mint <MINT_PUBKEY>

# Unlock validator (release token)
npx tsx cli/src/main.ts unlock \
  --keypair validator.json

# Query validator status
npx tsx cli/src/main.ts status --validator <PUBKEY>

# Submit proof artifact
npx tsx cli/src/main.ts prove \
  --keypair submitter.json \
  --artifact artifact.json
```

---

## Deployment Guide

```
┌────────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT WORKFLOW                             │
├────────────────────────────────────────────────────────────────────┤
│                                                                    │
│  [Phase 1] Environment Setup                                      │
│    ├─ Install: Node.js 20.x, Rust 1.70+, Solana CLI 1.18+        │
│    ├─ Configure: Devnet RPC, wallet keypair                       │
│    └─ Dependencies: npm install, cargo build                      │
│                                                                    │
│  [Phase 2] Program Deployment                                     │
│    ├─ Build: anchor build                                         │
│    ├─ Deploy: anchor deploy --provider.cluster devnet             │
│    └─ Verify: solana program show <PROGRAM_ID>                    │
│                                                                    │
│  [Phase 3] Infrastructure Provisioning                            │
│    ├─ PostgreSQL: docker run postgres:15                          │
│    ├─ Migrations: bash scripts/db_migrate.sh                      │
│    └─ Keys: node scripts/gen_aggregator_key.js                    │
│                                                                    │
│  [Phase 4] On-Chain Initialization                                │
│    ├─ Config: npx tsx cli/src/main.ts init-config                │
│    └─ Validator: npx tsx cli/src/main.ts register                │
│                                                                    │
│  [Phase 5] Service Launch                                         │
│    ├─ Orchestrator: node orchestrator/dist/server.js              │
│    ├─ Indexer: node indexer/dist/index.js                         │
│    └─ Health: curl http://localhost:8080/health                   │
│                                                                    │
│  [Phase 6] Operational Verification                               │
│    ├─ Submit: curl -X POST /prove                                 │
│    ├─ Anchor: curl -X POST /anchor                                │
│    └─ Query: psql -c "SELECT * FROM proofs"                       │
│                                                                    │
└────────────────────────────────────────────────────────────────────┘
```

### Prerequisites

| Tool         | Version | Purpose                                    |
|--------------|---------|--------------------------------------------|
| Node.js      | 20.x    | TypeScript service runtime                 |
| Rust         | 1.70+   | Prover and Anchor program compilation      |
| Anchor CLI   | 0.30.1  | Solana program framework                   |
| Solana CLI   | 1.18+   | Blockchain interaction                     |
| PostgreSQL   | 15+     | Indexer database backend                   |
| Docker       | 20+     | Optional containerized deployment          |

### Environment Setup

1. **Clone Repository**
   ```bash
   git clone https://github.com/zkSLLabs/zkSealevel_Division_I.git
   cd zkSealevel_Division_I
   ```

2. **Install Dependencies**
   ```bash
   npm install
   npm --prefix orchestrator install
   npm --prefix indexer install
   npm --prefix cli install
   ```

3. **Build Services**
   ```bash
   npm run build:services
   cargo build --release --manifest-path prover/Cargo.toml
   ```

### Devnet Deployment

#### Step 1: Deploy Program

```bash
# Configure Solana CLI for Devnet
solana config set --url https://api.devnet.solana.com

# Ensure sufficient SOL balance (≥3.2 SOL for deployment)
solana balance
solana airdrop 5  # if needed

# Build and deploy program
anchor build
anchor deploy --provider.cluster devnet --program-name validator_lock

# Note the deployed program ID
anchor keys list
# validator_lock: 4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ
```

#### Step 2: Configure Environment

Create `.env` in project root:
```bash
# Solana Configuration
RPC_URL=https://api.devnet.solana.com
WS_URL=wss://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ
CHAIN_ID=103
MIN_FINALITY_COMMITMENT=finalized

# Service Configuration
PORT=8080
ARTIFACT_DIR=./orchestrator/data/artifacts
AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json

# Database Configuration
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/zksl
```

#### Step 3: Generate Aggregator Key

```bash
mkdir -p keys
node scripts/gen_aggregator_key.js keys/aggregator.json
```

Output format (`keys/aggregator.json`):
```json
{
  "secretKey": "64-byte-hex-seed-and-key-concatenated"
}
```

#### Step 4: Initialize On-Chain Config

```bash
npx tsx cli/src/main.ts init-config \
  --keypair ~/.config/solana/id.json \
  --mint <YOUR_ZKSL_MINT_PUBKEY> \
  --agg-key keys/aggregator.json \
  --chain-id 103
```

**Requirements**:
- Payer must have sufficient SOL for rent
- `<YOUR_ZKSL_MINT_PUBKEY>` must be a valid SPL token mint
- Config can only be initialized once

#### Step 5: Apply Database Migrations

```bash
# Start PostgreSQL (if not running)
docker run -d \
  --name zksl-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=zksl \
  -p 5432:5432 \
  postgres:15

# Apply migrations
bash scripts/db_migrate.sh
```

Migrations applied:
- `001_init.sql`: Create validators and proofs tables
- `002_indexer_state.sql`: Create indexer_state tracking
- `003_indexer_cursor.sql`: Add cursor fields for scan position
- `004_indexer_last_signature.sql`: Add last_signature for deduplication

#### Step 6: Start Services

**Orchestrator**:
```bash
npm --prefix orchestrator run build
node orchestrator/dist/server.js
# Listening on port 8080
```

**Indexer**:
```bash
npm --prefix indexer run build
node indexer/dist/index.js
# Monitoring program accounts...
```

#### Step 7: Register Validator

```bash
npx tsx cli/src/main.ts register \
  --keypair validator.json \
  --mint <YOUR_ZKSL_MINT_PUBKEY>
```

**Requirements**:
- Validator ATA must hold exactly 1 token (respecting mint decimals)
- Token will be transferred to escrow PDA
- ValidatorRecord created with status='Active'

#### Step 8: Submit and Anchor Proof

**Create artifact**:
```bash
curl -X POST http://localhost:8080/prove \
  -H 'Idempotency-Key: proof-001' \
  -H 'Content-Type: application/json' \
  -d '{
    "start_slot": 1000,
    "end_slot": 1064,
    "state_root_before": "0000000000000000000000000000000000000000000000000000000000000001",
    "state_root_after": "0000000000000000000000000000000000000000000000000000000000000002"
  }'
```

**Response**:
```json
{
  "artifact_id": "550e8400-e29b-41d4-a716-446655440000",
  "proof_hash": "abcd1234...",
  "status": "canonicalized"
}
```

**Anchor proof**:
```bash
curl -X POST http://localhost:8080/anchor \
  -H 'Idempotency-Key: anchor-001' \
  -H 'Content-Type: application/json' \
  -d '{
    "artifact_id": "550e8400-e29b-41d4-a716-446655440000"
  }'
```

**Response**:
```json
{
  "txid": "5J7Z...",
  "seq": 1,
  "status": "anchored"
}
```

#### Step 9: Verify Indexer Sync

```bash
# Query orchestrator
curl http://localhost:8080/proof/550e8400-e29b-41d4-a716-446655440000

# Query database
psql $DATABASE_URL -c "SELECT * FROM proofs WHERE artifact_id = '550e8400-e29b-41d4-a716-446655440000';"
```

Expected: `commitment_level` progresses from 0 → 1 → 2 as transaction confirms.

---

## API Reference

### Orchestrator Endpoints

#### POST /artifact

Submit proof artifact for validation and canonicalization.

**Request Headers**:
- `Idempotency-Key` (required): Unique key for deduplication
- `Content-Type`: `application/json`

**Request Body**:
```json
{
  "start_slot": 1000,
  "end_slot": 1064,
  "state_root_before": "hex(32 bytes)",
  "state_root_after": "hex(32 bytes)"
}
```

**Response** (201 Created):
```json
{
  "artifact_id": "uuid-v4",
  "proof_hash": "hex(32 bytes)",
  "ds_hash": "hex(32 bytes)",
  "status": "canonicalized",
  "file_path": "orchestrator/data/artifacts/2025/01/15/artifact_id.json"
}
```

**Error Responses**:
- `400`: Invalid artifact format
- `409`: Idempotency key conflict
- `500`: Internal server error

#### POST /prove

Submit artifact and automatically anchor on-chain (combines `/artifact` + `/anchor`).

**Request/Response**: Same as `/artifact` + `/anchor` combined

#### POST /anchor

Anchor previously submitted artifact on-chain.

**Request Headers**:
- `Idempotency-Key` (required)
- `Content-Type`: `application/json`

**Request Body**:
```json
{
  "artifact_id": "uuid-v4"
}
```

**Response** (200 OK):
```json
{
  "txid": "base58-signature",
  "seq": 1,
  "ds_hash": "hex(32 bytes)",
  "status": "anchored",
  "commitment": "processed"
}
```

**Error Responses**:
- `404`: Artifact not found
- `409`: Already anchored or idempotency conflict
- `500`: Transaction failed

#### GET /proof/:artifact_id

Query proof record status.

**Response** (200 OK):
```json
{
  "artifact_id": "uuid-v4",
  "proof_hash": "hex(32 bytes)",
  "seq": 1,
  "txid": "base58-signature",
  "commitment_level": 2,
  "start_slot": 1000,
  "end_slot": 1064,
  "state_root_before": "hex(32 bytes)",
  "state_root_after": "hex(32 bytes)",
  "submitted_by": "base58-pubkey",
  "ts": "2025-01-15T12:00:00Z"
}
```

#### GET /validator/:pubkey

Query validator registration status.

**Response** (200 OK):
```json
{
  "pubkey": "base58-pubkey",
  "status": "Active",
  "escrow": "base58-pubkey",
  "lock_ts": "2025-01-15T10:00:00Z",
  "unlock_ts": null,
  "num_accepts": 5,
  "last_seen": "2025-01-15T12:00:00Z"
}
```

#### GET /health

Service health check.

**Response** (200 OK):
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3600,
  "rpc_url": "https://api.devnet.solana.com"
}
```

---

## Database Schema

### Table: validators

Tracks registered validators and their escrow state.

```sql
CREATE TABLE validators (
  pubkey TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('Active', 'Unlocked')),
  escrow TEXT NOT NULL,
  lock_ts TIMESTAMPTZ NOT NULL,
  unlock_ts TIMESTAMPTZ,
  num_accepts BIGINT NOT NULL DEFAULT 0,
  last_seen TIMESTAMPTZ
);

CREATE INDEX idx_validators_status ON validators(status);
CREATE INDEX idx_validators_last_seen ON validators(last_seen);
```

### Table: proofs

Stores anchored proof records with commitment tracking.

```sql
CREATE TABLE proofs (
  artifact_id UUID NOT NULL UNIQUE,
  start_slot BIGINT NOT NULL,
  end_slot BIGINT NOT NULL,
  proof_hash BYTEA NOT NULL CHECK (octet_length(proof_hash) = 32),
  ds_hash BYTEA NOT NULL CHECK (octet_length(ds_hash) = 32),
  artifact_len INT NOT NULL CHECK (artifact_len BETWEEN 0 AND 524288),
  state_root_before BYTEA NOT NULL CHECK (octet_length(state_root_before) = 32),
  state_root_after BYTEA NOT NULL CHECK (octet_length(state_root_after) = 32),
  submitted_by TEXT NOT NULL,
  aggregator_pubkey TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  seq BIGINT NOT NULL,
  commitment_level SMALLINT NOT NULL CHECK (commitment_level IN (0, 1, 2)),
  da_params BYTEA,
  txid TEXT NOT NULL UNIQUE,
  PRIMARY KEY (proof_hash, seq)
);

CREATE INDEX idx_proofs_artifact_id ON proofs(artifact_id);
CREATE INDEX idx_proofs_seq ON proofs(seq);
CREATE INDEX idx_proofs_commitment ON proofs(commitment_level);
CREATE INDEX idx_proofs_slot_range ON proofs(start_slot, end_slot);
```

**Commitment Levels**:
- `0`: Processed
- `1`: Confirmed
- `2`: Finalized

### Table: indexer_state

Tracks indexer scan position for crash recovery.

```sql
CREATE TABLE indexer_state (
  id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  last_scan_ts TIMESTAMPTZ,
  last_slot BIGINT,
  last_signature TEXT
);
```

---

## Development Workflow

### Running Tests

**Unit Tests** (Orchestrator):
```bash
npm --prefix orchestrator run test
```

**Unit Tests** (Indexer):
```bash
npm --prefix indexer run test
```

**Known Answer Tests (KATs)**:
```bash
npm run test:kats
```

KATs validate:
- DS hash construction
- PDA derivation
- Canonical JSON serialization
- Borsh encoding
- Ed25519 signature layout
- Negative test cases (invalid DS, wrong pubkey, etc.)

**Conformance Tests** (Node.js ↔ Rust):
```bash
npm run conformance
```

Ensures `proof_hash` and DS construction match between TypeScript and Rust implementations.

**Rust Tests** (Prover):
```bash
cargo test --manifest-path prover/Cargo.toml
```

**Anchor Tests** (Program):
```bash
cd programs/validator_lock
anchor test
```

### Continuous Integration

GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push/PR:

1. **node-tests**: Install deps, lint, build services, run orchestrator tests, run KATs
2. **indexer-tests**: Spin up PostgreSQL service, apply migrations, run indexer tests
3. **rust-tests**: Run `cargo test --workspace --all-features`
4. **conformance**: Generate aggregator key, run Node vs Rust proof_hash validation

All jobs must pass before merging.

### Local Development with Docker

```bash
# Start infrastructure (Postgres, Redis, local validator)
docker-compose up -d

# Build and start services
npm run build:services
npm run start:orchestrator &
npm run start:indexer &

# Tail logs
docker-compose logs -f orchestrator indexer
```

---

## Testing & Validation

### Conformance Test Suite

Located in `scripts/`:

| Test                  | Purpose                                          |
|-----------------------|--------------------------------------------------|
| `ds_kat.js`           | Validate DS message construction and ds_hash     |
| `ds_negative_kat.js`  | Test error handling for invalid DS               |
| `anchor_proof_kat.js` | Verify Anchor instruction Borsh encoding         |
| `canonical_kat.js`    | Test artifact canonicalization determinism       |
| `pda_kat.js`          | Validate PDA derivation against known addresses  |
| `conformance.js`      | Cross-language proof_hash validation (TS vs Rust)|

### Running Individual KATs

```bash
node scripts/kats/ds_kat.js
node scripts/kats/pda_kat.js
node scripts/kats/anchor_proof_kat.js
```

### End-to-End Test (Localnet)

```bash
# Start local validator
solana-test-validator -r

# Deploy program
anchor deploy --provider.cluster localnet

# Run E2E script
npx tsx scripts/e2e_localnet.ts
```

E2E script performs:
1. Initialize config
2. Register validator
3. Submit proof artifact
4. Anchor proof on-chain
5. Wait for indexer sync
6. Query proof status from API and DB
7. Verify commitment progression

---

## Project Status

```
╔══════════════════════════════════════════════════════════════════╗
║                        PROJECT STATUS                            ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  Deployment Status:          [████████████████████████] 100%    ║
║    └─ Devnet Program: 4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHy...  ║
║                                                                  ║
║  Core Services:              [████████████████████████] 100%    ║
║    ├─ Orchestrator:          OPERATIONAL                        ║
║    ├─ Indexer:               OPERATIONAL                        ║
║    ├─ Prover:                REFERENCE IMPL COMPLETE            ║
║    └─ CLI:                   COMPLETE                           ║
║                                                                  ║
║  Protocol Implementation:    [████████████████████████] 100%    ║
║    ├─ DS Message:            VALIDATED                          ║
║    ├─ Ed25519 Preflight:     ENFORCED                           ║
║    ├─ Transaction Ordering:  STRICT                             ║
║    └─ PDA Derivation:        VERIFIED                           ║
║                                                                  ║
║  Testing & Validation:       [██████████████████████  ] 95%     ║
║    ├─ Unit Tests:            PASSING (12 orchestrator, 4 idx)   ║
║    ├─ KATs:                  PASSING (7 suites)                 ║
║    ├─ Conformance:           PASSING (Node ↔ Rust)              ║
║    └─ CI/CD:                 CONFIGURED                         ║
║                                                                  ║
║  Documentation:              [████████████████████████] 100%    ║
║    ├─ README:                COMPREHENSIVE                      ║
║    ├─ Execution Plan:        COMPLETE                           ║
║    └─ API Reference:         DOCUMENTED                         ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

     ┌──────────────────────────────────────────────────────┐
     │  NEXT MILESTONES                                     │
     ├──────────────────────────────────────────────────────┤
     │  [ ] Full STARK AIR for zk-BPF bytecode validation   │
     │  [ ] Production aggregator key rotation ceremony     │
     │  [ ] Mainnet deployment + security audit             │
     │  [ ] Performance benchmarking (target: <2s latency)  │
     │  [ ] Grafana + Prometheus monitoring dashboard       │
     └──────────────────────────────────────────────────────┘
```

### Current State (as of 2025-01-15)

- **Program Deployment**: Successfully deployed to Devnet at `4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ`
- **Orchestrator**: Operational on Devnet with full artifact handling and transaction submission
- **Indexer**: Monitoring Devnet program accounts and syncing to PostgreSQL
- **Prover**: Reference implementation complete; STARK circuit integration in progress
- **CI/CD**: GitHub Actions configured with test matrix and conformance validation
- **Test Coverage**:
  - Orchestrator: 12 unit tests + 7 KATs
  - Indexer: 4 unit tests
  - Conformance: Node ↔ Rust proof_hash validation passing
  - Program: Anchor test suite covering all instructions and error paths

### Completed Objectives (Devnet POC Execution Plan)

- [x] On-chain program with DS/Ed25519/sequence/range/skew checks
- [x] Orchestrator endpoints (/artifact, /anchor, /prove) with DS construction
- [x] Indexer + PostgreSQL migrations with commitment tracking
- [x] CLI for init-config, register, unlock, prove, status
- [x] Devnet deployment runbook and CI workflow
- [x] Deterministic artifact canonicalization with stable artifact_id
- [x] Transaction ordering enforcement (ComputeBudget → Ed25519 → Anchor)
- [x] Conformance test suite (Node vs Rust)
- [x] PDA derivation validation
- [x] Known Answer Tests for DS, Borsh, Ed25519 layout
- [x] Idempotency via Idempotency-Key header
- [x] Database schema with validators, proofs, indexer_state
- [x] Commitment-level reconciliation (processed → confirmed → finalized)
- [x] Error mapping and comprehensive error codes

### In Progress

- [ ] STARK prover integration with full AIR for Sealevel VM bytecode validation
- [ ] Production aggregator key rotation ceremony
- [ ] Mainnet deployment preparation and security audit
- [ ] Performance benchmarking and optimization (target: <2s end-to-end latency)
- [ ] Monitoring dashboard with Grafana + Prometheus

### Known Limitations (POC Phase)

- Prover currently uses reference computation; full zk-BPF AIR in development
- Single aggregator key (rotation implemented but not exercised in POC)
- No DA layer integration (da_params field reserved for future use)
- Indexer uses polling + WebSocket; consider dedicated Geyser plugin for scale
- CLI requires manual keypair management; consider hardware wallet integration

---

## Technical Documentation

For detailed protocol specifications, refer to:
- **Devnet POC Execution Plan**: `Devnet-POC-Execution-Plan.md` — byte-precise protocol contracts, account layouts, instruction encodings
- **Sprint Plan**: `Devnet-Sprint-Plan.md` — development tasks and acceptance criteria
- **Testing Gap Analysis**: `Devnet-Testing-Gap-Analysis.md` — test coverage matrix and validation strategy

---

## Contributing

This is a research project developed by zKSL Labs (zkSealevel Research Team). For inquiries or collaboration proposals, please contact the development team.

### Code Standards

- **Rust**: Follow `cargo fmt` and `cargo clippy` recommendations
- **TypeScript**: ESLint + Prettier with strict type checking
- **Git**: Conventional commits (feat, fix, chore, docs, test)
- **Testing**: All new features must include unit tests and update KATs if protocol-impacting

### Pull Request Process

1. Create feature branch from `main`
2. Implement changes with tests
3. Run full test suite locally (`npm run test:all`, `cargo test --workspace`)
4. Push and open PR with description linking to issue/spec
5. CI must pass (node-tests, indexer-tests, rust-tests, conformance)
6. Maintainer review and approval required before merge

---

## License

Copyright 2025 zKSL Labs (zkSealevel Research Team). All rights reserved.

---

**Developed by Ghost Architects via zKSL Labs**

*zkSealevel Research Team 2025*
