# zkSealevel

Zero-Knowledge Proof System for Solana State Validation

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                zkSealevel                                    ║
║                    Zero-Knowledge Proof System for Solana                   ║
║                                                                              ║
║  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  ║
║  │   Prover    │───▶│Orchestrator │───▶│  Indexer    │───▶│ Validator   │  ║
║  │   Service   │    │   Service   │    │   Service   │    │  Registry   │  ║
║  └─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘  ║
║                                                                              ║
║  Features: ZK Proofs • State Validation • Solana Integration • Rust/TS     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Developed by Ghost Architects via zKSL Labs (zkSealevel Research Team 2025 ©)**

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Technical Specifications](#technical-specifications)
- [Environment Configuration](#environment-configuration)
- [Installation and Deployment](#installation-and-deployment)
- [Usage Examples](#usage-examples)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)

## Overview

zkSealevel is a zero-knowledge proof system designed for Solana validator state verification. The system enables privacy-preserving validation of Solana blockchain state through cryptographic proofs.

### Purpose and Scope

The system provides:
- Zero-knowledge proof generation for Solana state validation
- Validator registration and management
- Proof aggregation and verification
- State commitment tracking

## Architecture

The zkSealevel system consists of four main components:

### Core Components

1. **Prover Service** (Rust)
   - Generates zero-knowledge proofs
   - Processes state validation requests
   - Handles cryptographic operations

2. **Orchestrator Service** (TypeScript/Node.js)
   - Coordinates proof generation workflow
   - Manages validator registration
   - Provides REST API interface

3. **Indexer Service** (TypeScript/Node.js)
   - Monitors blockchain state
   - Tracks validator activities
   - Maintains synchronization

4. **CLI Tool** (TypeScript/Node.js)
   - Command-line interface for system interaction
   - Proof submission and verification
   - System status monitoring

### System Flow

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│    CLI      │───▶│Orchestrator │───▶│   Prover    │
│   Client    │    │   Service   │    │   Service   │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │                   ▼                   │
       │            ┌─────────────┐            │
       │            │  Database   │            │
       │            │ (PostgreSQL)│            │
       │            └─────────────┘            │
       │                   │                   │
       ▼                   ▼                   ▼
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Indexer   │    │  Validator  │    │   Solana    │
│   Service   │    │  Registry   │    │ Blockchain  │
└─────────────┘    └─────────────┘    └─────────────┘
```

## Technical Specifications

### Technology Stack

- **Backend Services**: Node.js with TypeScript
- **Proof Generation**: Rust
- **Database**: PostgreSQL
- **Blockchain**: Solana (Anchor framework)
- **Containerization**: Docker

### Supported Platforms

- Linux (primary)
- macOS
- Windows (with WSL recommended)

## Environment Configuration

### Required Environment Variables

```bash
# Service Configuration
PORT=3000
NODE_ENV=development

# Database Connection
DATABASE_URL=postgresql://user:password@localhost:5432/zksealevel

# Solana Configuration
RPC_URL=https://api.devnet.solana.com
PROGRAM_ID=your_program_id_here
CHAIN_ID=103

# Cryptographic Keys
AGG_KEY_PATH=./keys/aggregator.key

# File Paths
ARTIFACT_DIR=./artifacts
```

## Installation and Deployment

### Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Node.js | 18+ | Runtime for TypeScript services |
| Rust | 1.70+ | Prover service compilation |
| PostgreSQL | 13+ | Database backend |
| Docker | 20+ | Containerized deployment |

### Development Setup

1. **Clone Repository**
   ```bash
   git clone <repository-url>
   cd zkSealevel
   ```

2. **Install Dependencies**
   ```bash
   npm install
   ```

3. **Database Setup**
   ```bash
   # Run migrations
   psql -d zksealevel -f migrations/001_init.sql
   psql -d zksealevel -f migrations/002_indexer_state.sql
   ```

4. **Build Services**
   ```bash
   # Build all services
   npm run build
   
   # Build prover service
   cd prover && cargo build --release
   ```

5. **Start Services**
   ```bash
   # Start orchestrator
   npm run start:orchestrator
   
   # Start indexer
   npm run start:indexer
   ```

### Docker Deployment

```bash
# Build containers
docker-compose build

# Start services
docker-compose up -d
```

## Usage Examples

### CLI Commands

#### Proof Generation
```bash
# Generate proof
npx tsx cli/src/main.ts prove --input <input_file> --output <output_file>

# Check status
npx tsx cli/src/main.ts status
```

#### Anchor Operations
```bash
# Deploy program
npx tsx cli/src/main.ts anchor deploy

# Initialize program
npx tsx cli/src/main.ts anchor init
```

### API Endpoints

#### Orchestrator Service

**POST /prove**
- Generate zero-knowledge proof
- Request body: proof parameters
- Response: proof artifact

**GET /status**
- System status information
- Response: service health and metrics

**POST /validators**
- Register new validator
- Request body: validator information
- Response: registration confirmation

## Database Schema

### Tables

#### validators
```sql
CREATE TABLE validators (
  pubkey TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('Active','Unlocked')),
  escrow TEXT NOT NULL,
  lock_ts TIMESTAMPTZ NOT NULL,
  unlock_ts TIMESTAMPTZ,
  num_accepts BIGINT NOT NULL DEFAULT 0,
  last_seen TIMESTAMPTZ
);
```

#### proofs
```sql
CREATE TABLE proofs (
  artifact_id UUID NOT NULL UNIQUE,
  start_slot BIGINT NOT NULL,
  end_slot BIGINT NOT NULL,
  proof_hash BYTEA NOT NULL CHECK (octet_length(proof_hash)=32),
  ds_hash BYTEA NOT NULL CHECK (octet_length(ds_hash)=32),
  artifact_len INT NOT NULL CHECK (artifact_len BETWEEN 0 AND 524288),
  state_root_before BYTEA NOT NULL CHECK (octet_length(state_root_before)=32),
  state_root_after BYTEA NOT NULL CHECK (octet_length(state_root_after)=32),
  submitted_by TEXT NOT NULL,
  aggregator_pubkey TEXT NOT NULL,
  ts TIMESTAMPTZ NOT NULL,
  seq BIGINT NOT NULL,
  commitment_level SMALLINT NOT NULL CHECK (commitment_level IN (0,1,2)),
  da_params BYTEA,
  txid TEXT NOT NULL UNIQUE,
  PRIMARY KEY (proof_hash, seq)
);
```

#### indexer_state
```sql
CREATE TABLE indexer_state (
  id SMALLINT PRIMARY KEY DEFAULT 1,
  last_scan_ts TIMESTAMPTZ
);
```

## API Reference

### Data Types

#### Artifact
```typescript
interface Artifact {
  artifact_id: string;
  start_slot: number;
  end_slot: number;
  proof_hash: string;
  ds_hash: string;
  artifact_len: number;
  state_root_before: string;
  state_root_after: string;
  submitted_by: string;
  aggregator_pubkey: string;
  ts: string;
  seq: number;
  commitment_level: number;
  da_params?: string;
  txid: string;
}
```

### Service Configuration

#### Orchestrator
- Port: Configurable via PORT environment variable
- Database: PostgreSQL connection via DATABASE_URL
- Solana RPC: Configurable via RPC_URL

#### Prover
- Input/Output: File-based artifact processing
- Cryptographic keys: Configurable key paths
- Chain integration: Supports multiple chain IDs

#### Indexer
- Blockchain monitoring: Continuous state synchronization
- Database updates: Maintains validator and proof records
- State tracking: Persistent scan position storage


