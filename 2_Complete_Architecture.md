### zkSealevel (zKSL) — Complete Architecture (Build-Ready)

Date: October 2025
Source of truth: Master_Blueprint.md (this document restates it as a consolidated, build-ready architecture without introducing new scope.)

---

#### 1) Non‑Negotiable Scope and Goals
- Deliver a demonstrable, end-to-end product on localnet/devnet/testnet that proves Validator Lock and prover→verifier attestation anchored on Solana.
- MVP trust model: acceptance == DS-signed attestation by Aggregator (single key, with non-halt rotation). No on-chain ZK verification in MVP.
- No new features beyond Master_Blueprint.md; this document concretizes what to build.

---

#### 2) Components and Responsibilities
- On-chain program (`validator_lock`): Validator escrow (1 zKSL), proof anchoring, configuration, and state tracking.
- Prover/Aggregator (Rust): Produce canonical artifacts, compute proof_hash, build DS, sign DS, and submit anchor.
- Orchestrator/CLI (TypeScript): Developer UX, DS construction, transaction preflight/ComputeBudget, command-line flows.
- Indexer (TS or Rust): RPC subscription/polling, finality tracking, DB writes, rollback on reorg, API for dashboard.
- Optional Web (Next.js): Dashboard for validator status, latest anchors, and finality.

---

#### 3) On‑Chain Program (Anchor)
Accounts (PDA, Anchor/Borsh, little-endian ints):
- Config (168 bytes):
  - zksl_mint: Pubkey (32)
  - admin: Pubkey (32)
  - aggregator_pubkey: Pubkey (32)
  - next_aggregator_pubkey: Pubkey (32)
  - activation_seq: u64 (8)
  - chain_id: u64 (8)
  - paused: u8 (1)
  - bump: u8 (1)
  - reserved: [u8; 14] (padding)
- ValidatorRecord (136 bytes):
  - validator_pubkey: Pubkey (32)
  - lock_token_account: Pubkey (32)
  - lock_timestamp: i64 (8)
  - status: u8 (0=Active,1=Unlocked)
  - num_accepts: u64 (8)
  - reserved: [u8; 47]
- ProofRecord (262 bytes):
  - artifact_id: [u8;16] (uuid bytes)
  - start_slot: u64, end_slot: u64
  - proof_hash: [u8;32]
  - artifact_len: u32
  - state_root_before: [u8;32], state_root_after: [u8;32]
  - submitted_by: Pubkey (32), aggregator_pubkey: Pubkey (32)
  - timestamp: i64, seq: u64
  - ds_hash: [u8;32]
  - commitment_level: u8 (0=processed,1=confirmed,2=finalized)
  - da_params: [u8;12] (packed k,m,q,flags)
  - reserved: [u8;7]
- AggregatorState (134 bytes):
  - aggregator_pubkey: Pubkey (32)
  - last_seq: u64 (8)
  - reserved: [u8; 86]
- RangeState (136 bytes):
  - last_end_slot: u64 (8)
  - reserved: [u8;120]
- ValidatorEscrow: SPL Token ATA (PDA), rent-exempt, holds exactly 1 token while Active. Escrow and ATA derivations MUST use the mint’s token program (Token Program or Token‑2022); implementations SHOULD use SPL token interface compatibility.

Seeds (UTF-8):
- Config: ["zksl","config"],
- ValidatorRecord: ["zksl","validator", validator_pubkey],
- ValidatorEscrow: ["zksl","escrow", validator_pubkey],
- ProofRecord: ["zksl","proof", proof_hash, seq_le_bytes],
- AggregatorState: ["zksl","aggregator", aggregator_pubkey],
- RangeState: ["zksl","range"].

Constants (normative):
- MAX_SLOTS_PER_ARTIFACT=2048; MAX_ARTIFACT_SIZE_BYTES=524288; MAX_CLOCK_SKEW_SECS=120.

Instructions (preconditions/effects):
- initialize(zksl_mint, admin, aggregator_pubkey, next_aggregator_pubkey, activation_seq, chain_id)
  - Creates Config.
- register_validator(validator_pubkey)
  - Preconditions: escrow ATA derivation matches; source ATA mint == zksl_mint; transfer exactly 1 token (`10^decimals` base units, where `decimals` is read from the `ZKSL_MINT` mint); rent-exempt escrow.
  - Effects: sets ValidatorRecord status=Active.
- anchor_proof(artifact_id, start_slot, end_slot, proof_hash, state_root_before, state_root_after, aggregator_pubkey, timestamp, seq, ds_hash)
  - Accounts: config, aggregator_state, range_state, proof_record, submitted_by, sysvar_instructions, sysvar_clock.
  - Preconditions: paused==0; DS = "zKSL/anchor/v1" (14-byte ASCII) || chain_id || program_id || proof_hash || start_slot || end_slot || seq; exactly one Ed25519 preflight at index (ix-1) signs DS; reject any Ed25519 with bytes≠DS or len≠|DS|; ds_hash==blake3(DS);
    aggregator key acceptance: if seq>=activation_seq, key may be next_aggregator_pubkey else must be aggregator_pubkey; seq==last_seq+1; end_slot≥start_slot; window length≤MAX_SLOTS_PER_ARTIFACT; start_slot==last_end_slot+1; |timestamp-Clock|≤MAX_CLOCK_SKEW_SECS.
  - Effects: write ProofRecord (including commitment_level observed via RPC), update AggregatorState.last_seq=seq, RangeState.last_end_slot=end_slot; emit ProofAnchored(ds_hash); increment ValidatorRecord.num_accepts.
- unlock_validator()
  - Preconditions: status==Active; escrow balance==1.
  - Effects: close escrow to validator ATA; status=Unlocked.
- update_config(params)
  - Admin-only; updates aggregator_pubkey/next_aggregator_pubkey/activation_seq/paused; emits ConfigUpdated.

Events:
- ValidatorRegistered, ProofAnchored{ds_hash}, ValidatorUnlocked, ConfigUpdated{…}, Equivocation (Phase 2 placeholder).

Error codes (selected):
- InvalidMint, InvalidLockAmount, AlreadyRegistered, NotRegistered, EscrowMismatch, InvalidSignature, AggregatorMismatch, ProofAlreadyAnchored, StatusNotActive, MathOverflow, Paused, Unauthorized, NonMonotonicSeq, RangeOverlap, ClockSkew, BadEd25519Order, BadDomainSeparation, InsufficientBudget.

---

#### 4) Off‑Chain Services
Prover/Aggregator (Rust):
- Produce canonical artifact (JCS, UTF‑8), compute proof_hash = blake3(canonical_json_bytes), build DS from (chain_id, program_id, proof_hash, start_slot, end_slot, seq), sign DS (ed25519), submit anchor.
- Persist artifacts to local filesystem or S3/MinIO; object path: artifacts/YYYY/MM/DD/<artifact_id>.json; artifact_len recorded.

Orchestrator/CLI (TypeScript):
- Enforces ComputeBudget units ≥ 200_000 or rejects submission (InsufficientBudget).
- Reads PROGRAM_ID_VALIDATOR_LOCK, CHAIN_ID, RPC_URL from env; builds DS exactly as on‑chain.
- Commands:
  - zksl register --keypair <PATH> --mint <MINT> [--rpc-url <URL>] [--cluster localnet|devnet|testnet]
  - zksl prove --input <STATE_SNAPSHOT|TX_LOG> --out <ARTIFACT_PATH>
  - zksl anchor --artifact <ARTIFACT_PATH> --keypair <AGG_KEY>
  - zksl status --validator <PUBKEY>
  - zksl unlock --keypair <PATH>
- Logging: human by default; --json outputs structured logs.

Indexer:
- Polls/streams anchors; writes DB; tracks finality (processed/confirmed/finalized); rollbacks on reorg adjust RangeState downstream.

Optional Web:
- Displays live anchors (seq, start..end, commitment_level), validators, and gauges (locked supply).

---

#### 5) Data Formats and Crypto
- Canonical JSON (JCS): keys sorted, no extra whitespace; integers base‑10 strings.
- DS: "zKSL/anchor/v1" (14 ASCII bytes) || chain_id (LE u64) || program_id (32) || proof_hash (32) || start_slot (LE u64) || end_slot (LE u64) || seq (LE u64).
- ds_hash = blake3(DS) stored in ProofRecord and emitted in event.
- Ed25519 preflight: must be the immediately preceding instruction (ix‑1) and the only Ed25519 syscall in the tx.

---

#### 6) HTTP APIs (Orchestrator)
- Base: http://localhost:8080
- Idempotency: Idempotency-Key header required for POSTs.
- Error schema: {"error": {"code": <string>, "message": <string>, "details": <object|null>}}
- Endpoints:
  - GET /health → { status:"ok", version }
  - POST /artifact → body = canonical artifact JSON → { artifact_id, proof_hash }
  - POST /anchor → body = { artifact_id } → server computes proof_hash, builds DS, signs DS, submits anchor with ds_hash → { aggregator_signature, ds_hash, transaction_id }
  - GET /proof/:artifact_id → full artifact + on‑chain/indexed status
  - GET /validator/:pubkey → ValidatorRecord projection

---

#### 7) Environment and Configuration
- Common: RPC_URL, WS_URL, PROGRAM_ID_VALIDATOR_LOCK, ZKSL_MINT (mainnet: `9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump`), CHAIN_ID (u64), MIN_FINALITY_COMMITMENT=processed|confirmed|finalized (default finalized)
- Prover/Aggregator: ARTIFACT_DIR, AGGREGATOR_KEYPAIR_PATH
- Orchestrator: PORT; reads PROGRAM_ID_VALIDATOR_LOCK for DS
- Indexer: DATABASE_URL, REDIS_URL

---

#### 8) Database Schema (Postgres)
Tables:
- validators(pubkey TEXT PRIMARY KEY, status TEXT CHECK status IN ('Active','Unlocked') NOT NULL, escrow TEXT NOT NULL, lock_ts TIMESTAMPTZ NOT NULL, unlock_ts TIMESTAMPTZ, num_accepts BIGINT NOT NULL DEFAULT 0, last_seen TIMESTAMPTZ)
- proofs(
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
)
- metrics(name TEXT, ts TIMESTAMPTZ, value DOUBLE PRECISION)

Indexes:
- CREATE INDEX ON proofs (proof_hash);
- CREATE INDEX ON proofs (ts);
- CREATE INDEX ON proofs (ds_hash);
- CREATE INDEX proofs_range_idx ON proofs (start_slot, end_slot);
- CREATE INDEX ON validators (status);
- CREATE INDEX ON validators (last_seen);

---

#### 9) Operational Policy
- Finality: Indexer/UI marks anchors tentative until finalized; on reorg, revoke rows and recompute RangeState.
- ComputeBudget: Orchestrator requires ≥200k CU; rejects otherwise.
- Healthchecks: postgres pg_isready; redis ping; orchestrator /health; indexer /health.
- Resource limits (dev defaults): CPU 1.0, memory 512Mi per service (tune via benchmarks).

---

#### 10) Docker Compose (Service Map)
- solana: solana-test-validator (ports 8899, 8900) + ledger volume
- postgres: 15.x (5432) + pgdata volume
- redis: 7.2 (6379)
- prover: Rust, mounts ARTIFACT_DIR
- orchestrator: Node 20 (8080)
- indexer: Node/Rust, depends on postgres+solana
- prometheus/grafana: optional (9090, 3000)

---

#### 11) Quality Gates and Tests (Build-Stopper Rules)
- Lint/build/test/coverage/security gates as per Code Quality and Testing Policy in Master_Blueprint.md.
- KATs to include: DS literal length (14), DS hash fixed vector, escrow invariants, cross-program replay (DS), instruction-order fuzz (BadEd25519Order), overlap/seq (RangeOverlap, NonMonotonicSeq), clock skew (ClockSkew).
- Integration: faucet→register→prove→anchor→status→unlock with deterministic seeds; assert ProofRecord bytes and DB rows.

---

#### 12) Demonstration Runbook (Happy Path)
1. docker compose up -d
2. ./scripts/dev_bootstrap.sh (builds, deploys program, configures env/mint)
3. zksl register --keypair ./keys/validator.json --mint <MINT> --cluster devnet
   (Use `<MINT>` = a test mint on devnet/localnet; production deployments MUST set `ZKSL_MINT` to the live pump.fun mint.)
4. zksl prove --input sample_state.json --out ./data/artifacts/A.json
5. zksl anchor --artifact ./data/artifacts/A.json --keypair ./keys/aggregator.json
6. zksl status --validator <PUBKEY>
7. zksl unlock --keypair ./keys/validator.json

Expected outcomes: escrow balance=1 while Active; ProofRecord written with ds_hash, seq, start..end; commitment_level tracked; UI shows tentative→finalized.

---

#### 13) Release Criteria (Pilot‑Grade)
- All CI gates green; zero warnings; coverage thresholds met.
- DS KATs pass; no replay/overlap/seq violations; reorg rollback verified.
- README one‑command boot works on clean machine; .env.example contains CHAIN_ID and PROGRAM_ID_VALIDATOR_LOCK.
- proofs_range_idx exists in first migration; dashboards populate.

---

#### 14) Out‑of‑Scope (Future Phases)
- Threshold signatures (t‑of‑n), full DA sampling network, on‑chain ZK verification, slashing.
- Governance by $zKSL token holders.

This architecture is complete and shippable for localnet/devnet/testnet MVP.


