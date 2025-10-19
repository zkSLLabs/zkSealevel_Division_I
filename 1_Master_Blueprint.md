### zkSealevel (zKSL) — Master Blueprint

**Date:** October 2025

#### 0) Purpose and Scope (single page)
- **Goal:** Deliver a steel-thread prototype proving the Validator Lock and prover→verifier flow, anchored on Solana, with clear, repeatable demo steps. No heavy on-chain ZK; verify off-chain, anchor on-chain.
- **Token standard:** `$zKSL` (validator license; refundable lock, not a fee).
- **Success criteria:** Anyone can run the local demo, register as a validator by locking 1 `$zKSL`, submit a “proof artifact,” and observe on-chain acceptance and UI reflection of finality.

---

#### 1) System Overview
- **Problem:** Re-execution imposes hardware centralization pressure.
- **Approach:** Replace re-execution with cryptographic verification. In MVP, verification is off-chain with signature attestation and on-chain anchoring; future phases integrate STARK proofs.
- **Core mechanism:** Validator must lock 1 `$zKSL` to participate (the “Validator Lock”).

---

#### 2) Architecture (MVP → Phased ZK)
- **On-chain (Solana + Anchor):**
  - `validator_lock` program: manages validator registration via 1-token lock, records validator state, supports unlock.
  - `proof_registry` module (within same program or separate): stores accepted proof commitments (hashes) and associated metadata; verifies aggregator signatures via Solana ed25519 syscall.
- **Off-chain services:**
  - Prover/aggregator daemon (Rust): produces a deterministic proof artifact for a micro-batch (mock initially), builds the domain-separated message `DS` from artifact/chain fields and signs `DS`, then submits an on-chain anchor.
  - Orchestrator/CLI (TypeScript/Node): developer workflows, validator registration, artifact submission, status queries.
- **Data availability (prototype):**
  - Store full artifact in local filesystem or object storage; commit only content-addressed hash on-chain.
  - Optional: erasure coding with `reed-solomon-erasure` for a DA demo; simple sampler.
- **ZK Phases:**
  - MVP: Mock proof artifact + aggregator ed25519 signature; on-chain acceptance of hash via signature verification.
  - Phase 2: Integrate a STARK stack off-chain (e.g., RISC Zero or Winterfell) to produce real proofs over a constrained trace; still anchor hash on-chain.
  - Phase 3: Introduce recursion/streaming for scalability; explore Verkle/Sparse Merkle state commitments.

---

#### 3) Tech Stack and Rationale
- **On-chain:** Rust + Anchor; Anchor SPL for token escrow. Runs on `solana-test-validator` for demo.
- **Off-chain:**
  - Rust for prover/crypto-heavy artifact creation and signing.
  - TypeScript/Node for CLI and thin API server.
- **ZK libraries (Phase 2+):** RISC Zero or Winterfell (off-chain verification), with on-chain hash anchoring.
- **Persistence:** Postgres (or SQLite for MVP) for indexing and UI queries.
- **Queues/Events:** Redis (MVP) or NATS.
- **Frontend (optional, single page):** Next.js + Tailwind for validator dashboard.
- **Dev environment:** WSL2 recommended on Windows for Rust/Solana toolchains; Docker Compose for one-command local stack.

---

#### 4) On-chain Program Design (Anchor)
- **Accounts:**
  - `Config` (PDA): `zksl_mint`, `admin` (optional for upgrades), bumps.
  - `ValidatorRecord` (PDA per validator): `validator_pubkey`, `lock_token_account`, `lock_timestamp`, `status` (Active|Unlocked), `num_accepts`.
  - `ValidatorEscrow` (PDA token account): holds exactly 1 `$zKSL` per active validator.
  - `ProofRecord` (PDA per artifact): `artifact_id`, `block_range`, `proof_hash`, `state_root_before`, `state_root_after`, `submitted_by`, `aggregator_pubkey`, `timestamp`.
- **Instructions:**
  - `initialize(config)`: set `zksl_mint`; one-time.
  - `register_validator(validator_pubkey)`: transfers exactly 1 `$zKSL` from validator’s ATA into `ValidatorEscrow`; creates `ValidatorRecord` with `status=Active`.
  - `anchor_proof(artifact)`: verifies ed25519 signature provided via syscall; writes `ProofRecord` and emits event; increments `num_accepts` on active validators (for demo metrics).
  - `unlock_validator()`: requires `ValidatorRecord.status=Active`; closes escrow back to validator’s ATA; sets `status=Unlocked`.
- **Constraints:**
  - Lock amount fixed at 1 token; mint is `zksl_mint` from `Config`.
  - No slashing in MVP; refundable bond by design.

---

#### 5) Off-chain Services and Interfaces
- **Prover/Aggregator (Rust):**
  - Watches local validator for new micro-batches or consumes a synthetic workload.
  - Generates `ProofArtifact`, computes `proof_hash = blake3(canonical_json_bytes)`, builds the domain-separated message `DS` per Section 23, and signs `DS` using the aggregator keypair.
  - Submits `anchor_proof` with `ds_hash` and metadata; the transaction MUST include an Ed25519 preflight verifying `DS` per Section 20.
- **Artifact schema (canonical, JSON-serialized for MVP):**
  - `artifact_id` (uuid)
  - `block_range` { `start_slot`, `end_slot` }
  - `state_root_before`, `state_root_after` (32-byte hex)
  - `trace_commitment` (Merkle root, 32-byte hex)
  - `proof_hash` (blake3 hex of full artifact)
  - `aggregator_pubkey` (base58)
  - `aggregator_signature` (ed25519 over DS)
  - `timestamp` (unix seconds)
- **Orchestrator/CLI (TypeScript):**
  - `zksl register` → calls `register_validator` after mint/ATA checks.
  - `zksl prove` → triggers prover; writes artifact to storage; submits `anchor_proof`.
  - `zksl status` → reads `ValidatorRecord`, latest `ProofRecord`s; prints concise state.
  - `zksl unlock` → calls `unlock_validator` and confirms token return.

---

#### 6) Data and State Commitments (Prototype)
- **State root:** Start with Sparse Merkle Tree (SMT) root over a toy key-value state; in MVP, compute in prover and include in artifact.
- **Trace commitment:** Merkle root over per-tx traces (mocked in MVP; real in Phase 2+).
- **Data availability:** Store full artifact in filesystem or S3-compatible store; record only `proof_hash` on-chain.

---

#### 7) Operational Flows (Happy-path)
1. Mainnet: acquire 1 `$zKSL` (pump.fun mint `9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump`). Devnet/localnet: use a temporary test mint for demos; production points to the live mint via `ZKSL_MINT`.
2. `zksl register` locks 1 token via `ValidatorEscrow`; `ValidatorRecord.status=Active`.
3. `zksl prove` produces artifact for slots [N..M], computes `proof_hash`, builds DS and signs DS.
4. `anchor_proof` transaction stores `ProofRecord`; UI shows batch accepted (finality proxy for demo).
5. `zksl unlock` returns the 1 `$zKSL` to validator ATA; `status=Unlocked`.

---

#### 8) Security and Economics (MVP stance)
- **Security:**
  - On-chain verifies aggregator ed25519 signature only; no on-chain ZK.
  - Deterministic artifact hashing prevents tampering; content-addressed storage aids reproducibility.
- **Economics:**
  - Validator Lock: 1 `$zKSL` per active validator; refundable; creates structural demand and engineered scarcity as validator set grows.
  - No emissions, fees, or slashing logic in MVP; focus is the lock and verification path.
  - Trust statement (MVP): Acceptance == valid signature(s) from AggregatorSet (per Sections 31 and 20); it is not cryptographic execution proof verification on-chain.

---

#### 9) Deliverables and Acceptance Criteria
- **On-chain program:** compiled and deployed to local validator; Anchor IDL exported.
- **CLI:** `register`, `prove`, `status`, `unlock` commands working end-to-end.
 - **Prover/Aggregator:** produces deterministic artifacts; anchors proof hash with DS signature; signature verified on-chain.
- **Demo runbook:** one command brings up stack via Docker Compose; README steps succeed on fresh machine.
- **Acceptance tests:** integration script executes full flow and asserts: lock balance, `ValidatorRecord` state, `ProofRecord` creation, and token return.

---

#### 10) Milestones and Timeline (indicative 2–3 weeks)
- **Week 1:** On-chain `validator_lock` + escrow; CLI `register`/`unlock`; integration tests.
- **Week 2:** Prover (mock trace) + aggregator signing; `anchor_proof`; dashboard or CLI `status` with indexer.
- **Week 3:** Optional real ZK integration (RISC Zero or Winterfell) over a constrained trace; artifact includes proof reference; performance measurements.

---

#### 11) Repository Layout
- `programs/validator_lock` (Anchor program)
- `cli/` (TypeScript commands)
- `prover/` (Rust daemon, artifact generator)
- `indexer/` (TS or Rust, writes Postgres)
- `web/` (optional Next.js dashboard)
- `docker/compose.yml` (local stack)
- `README.md` (runbook)

---

#### 12) Observability and Tooling
- **Logging/metrics:** `tracing` (Rust), Prometheus + Grafana (Docker)
- **Keys:** Deterministic dev keys; secrets via `.env` in local only.
- **CI:** GitHub Actions: build program, run tests, lint CLI, run prover unit tests.

---

#### 13) Risks and Mitigations
- **On-chain compute limits:** Keep anchoring minimal (hash + signer check); push heavy work off-chain.
- **ZK integration complexity:** Start with mock; phase-in real ZK with narrow scope.
- **Data availability UX:** Begin with local storage; abstract with content addressing for future DA backends.
- **Windows dev friction:** Recommend WSL2; provide Dockerized flows.

---

#### 14) Future Work (post-MVP)
- Real STARK proofs for a chosen instruction subset; recursion and batching.
- Verkle trees for state; light client verification.
- Slashing/dispute protocol; decentralized aggregator set.
- DA via erasure-coded sampling network.
- Incentive model extensions (fees, rewards) tied to proof acceptance.

---

#### 15) Definitions
- **Validator Lock:** Requirement to lock 1 `$zKSL` token in program escrow to register as an active validator; fully refundable on unlock.
- **Proof Artifact:** Off-chain bundle describing a batch’s execution commitment; content-addressed; hash anchored on-chain, signed by aggregator.
- **Anchor Proof:** On-chain transaction storing `proof_hash` and metadata after signature verification; serves as finality proxy in MVP.



---

#### 16) Versions Matrix (normative)
- **Operating system (dev):** Ubuntu 22.04 LTS (WSL2 on Windows 11 is acceptable)
- **Solana toolchain:** `solana-cli 1.18.x` (pin via Docker image tag and `solana --version` check)
- **Anchor:** `anchor-cli 0.30.x` (compatible with Solana 1.18)
- **Rust toolchain:** `rustc 1.80+`, `cargo 1.80+`, components: `clippy`, `rustfmt`
- **Node.js:** `v20.x LTS`
 
 - **Package manager:** `pnpm 9.x` (normative)
- **TypeScript:** `5.4.x`
- **Postgres:** `15.x`
- **Redis:** `7.2.x`
- **Prometheus:** `2.49.x`
- **Grafana:** `10.4.x`
- **ZK libraries (Phase 2+ only):** `risc0 0.20+` or `winterfell 0.7+` (off-chain)
- **Crypto libs (Rust):** `blake3 1.5.x`, `ed25519-dalek 2.1.x`, `serde 1.0.x`, `serde_json 1.0.x`
- **Anchor SPL (Rust):** `anchor-spl 0.30.x` (SPL Token extensions)

Notes:
- Exact versions MUST be pinned via lockfiles and container image digests; the above ranges are guidance. Build scripts SHALL fail if versions drift.
- All Docker images SHALL be referenced by immutable digests in `docker/compose.yml` to guarantee reproducibility.

---

#### 17) Deterministic Setup and Build (normative)
- Environment prerequisites:
  - Install Docker (24.x+) and Docker Compose plugin.
  - On Windows, enable WSL2 and use Ubuntu 22.04.
  - Install `just` (optional) or use provided shell scripts.
- Toolchain pinning:
  - Rust: use `rustup toolchain install stable` and `rustup override set stable` in each Rust project directory; commit `rust-toolchain.toml`.
  - Node: use `volta` or `nvm` to pin Node 20.x; commit `.nvmrc` or `package.json` `engines`.
  - Package manager: use `pnpm` with a committed `pnpm-lock.yaml`. Always run `pnpm install --frozen-lockfile`.
- Build commands (reference):
  - On-chain: `anchor build` (produces program `.so`, IDL); `anchor keys list` to confirm IDs.
  - Prover (Rust): `cargo build --release` (produces `prover` binary).
  - CLI (TypeScript): `pnpm build`; optionally produce standalone binaries via `pkg`.
- Reproducibility rules:
  - All builds MUST execute inside pinned Docker images in CI to ensure consistent linkage.
  - Environment variables MUST be read from `.env` checked in as `.env.example` with non-secret defaults; secrets are set at runtime.
  - CI SHALL verify checksums for build artifacts and emit SBOMs.

---

#### 18) Constants and Seeds (normative)
- Program IDs:
  - `validator_lock` program ID: assigned at deploy; recorded in `Anchor.toml` and CLI config.
- PDA seeds (UTF-8 literals unless specified):
  - `Config`: seeds = `[b"zksl", b"config"]`
  - `ValidatorRecord`: seeds = `[b"zksl", b"validator", validator_pubkey]`
  - `ValidatorEscrow`: seeds = `[b"zksl", b"escrow", validator_pubkey]`
  - `ProofRecord`: seeds = `[b"zksl", b"proof", proof_hash, seq_le_bytes]`
  - `AggregatorState`: seeds = `[b"zksl", b"aggregator", aggregator_pubkey]`
  - `RangeState`: seeds = `[b"zksl", b"range"]`
- Discriminators: Standard Anchor 8-byte account discriminators (SHA256 of namespace).
- Lock amount: exactly 1 token = `10^decimals` base units, where `decimals` is read from the `ZKSL_MINT` mint. No 0‑decimals assumption.
- Compute budget (anchor_proof): target 200,000 CU; adjust via `ComputeBudget` instructions if required.

---

#### 19) Account Layouts and Byte Sizes (normative)
All sizes include the 8-byte Anchor discriminator.

- `Config` (fixed-size):
  - Fields: `zksl_mint: Pubkey (32)`, `admin: Pubkey (32)`, `aggregator_pubkey: Pubkey (32)`, `next_aggregator_pubkey: Pubkey (32)`, `activation_seq: u64 (8)`, `chain_id: u64 (8)`, `paused: u8 (1)`, `bump: u8 (1)`, `reserved: [u8; 12]`.
  - Size: `8 + 32 + 32 + 32 + 32 + 8 + 8 + 1 + 1 + 12 = 166` bytes → pad reserved to keep 8-byte alignment: `reserved: [u8; 14]` → `168` bytes total.

- `ValidatorRecord` (fixed-size):
  - Fields: `validator_pubkey: Pubkey (32)`, `lock_token_account: Pubkey (32)`, `lock_timestamp: i64 (8)`, `status: u8 (1)` where `0=Active,1=Unlocked`, `num_accepts: u64 (8)`, `reserved: [u8; 47]`.
  - Size: `8 + 32 + 32 + 8 + 1 + 8 + 47 = 136` bytes.

- `ValidatorEscrow` (token account is SPL-owned; no custom layout aside from PDA derivation).

- `ProofRecord` (fixed-size):
  - Fields: `artifact_id: [u8; 16] (uuid)`, `start_slot: u64 (8)`, `end_slot: u64 (8)`, `proof_hash: [u8; 32]`, `artifact_len: u32 (4)`, `state_root_before: [u8; 32]`, `state_root_after: [u8; 32]`, `submitted_by: Pubkey (32)`, `aggregator_pubkey: Pubkey (32)`, `timestamp: i64 (8)`, `seq: u64 (8)`, `ds_hash: [u8; 32]`, `commitment_level: u8 (1)`, `da_params: [u8; 12]` (packed k,m,q,flags), `reserved: [u8; 7]`.
  - Size: `8 + 16 + 8 + 8 + 32 + 4 + 32 + 32 + 32 + 32 + 8 + 8 + 32 + 1 + 12 + 7 = 262` bytes.

Note: Reserved bytes allow future extension without breaking ABI.

- `AggregatorState` (fixed-size):
  - Fields: `aggregator_pubkey: Pubkey (32)`, `last_seq: u64 (8)`, `reserved: [u8; 86]`.
  - Size: `8 + 32 + 8 + 86 = 134` bytes.

- `RangeState` (fixed-size):
  - Fields: `last_end_slot: u64 (8)`, `reserved: [u8; 120]`.
  - Size: `8 + 8 + 120 = 136` bytes.

---

#### 20) Instruction ABI and Events (normative)
- `initialize(zksl_mint: Pubkey, admin: Pubkey, aggregator_pubkey: Pubkey)`
  - Accounts: `payer (signer)`, `config (PDA)`, `system_program`, `rent` (if needed)
  - Effects: creates `Config` with provided keys.

- `register_validator(validator_pubkey: Pubkey)`
  - Accounts: `validator (signer)`, `config`, `validator_record (PDA)`, `validator_escrow (PDA token account)`, `validator_ata`, `token_program`, `associated_token_program`, `system_program`.
  - Effects: transfers exactly 1 `$zKSL` from `validator_ata` to `validator_escrow`; sets record `status=Active`.

- `anchor_proof(artifact_id: [u8;16], start_slot: u64, end_slot: u64, proof_hash: [u8;32], state_root_before: [u8;32], state_root_after: [u8;32], aggregator_pubkey: Pubkey, timestamp: i64, seq: u64, ds_hash: [u8;32])`
  - Accounts: `config`, `aggregator_state (PDA)`, `range_state (PDA)`, `proof_record (PDA)`, `submitted_by (signer)`, `system_program`, `sysvar_instructions` (to verify prior Ed25519 instruction), `sysvar_clock`.
  - Preconditions:
    1) `config.paused == 0`.
    2) Domain separation message `DS = "zKSL/anchor/v1" || chain_id || program_id || proof_hash || start_slot || end_slot || seq` (all little-endian for integers) MUST be signed by `aggregator_pubkey` in the instruction at index `current_ix_index - 1` with an Ed25519 syscall. Reject if any Ed25519 syscall in the transaction signs a message whose bytes ≠ `DS` or whose length ≠ `len(DS)`. Require `ds_hash == blake3(DS)`; otherwise reject with `BadEd25519Order` or `BadDomainSeparation`.
    3) Aggregator key acceptance: if `seq >= config.activation_seq` then key may be `config.next_aggregator_pubkey` else must be `config.aggregator_pubkey`.
    4) Sequencing: `seq == AggregatorState.last_seq + 1`.
    5) Slot window: `end_slot >= start_slot` and `(end_slot - start_slot + 1) <= MAX_SLOTS_PER_ARTIFACT`.
    6) Range monotonicity (no overlaps): `start_slot == range_state.last_end_slot + 1`.
    7) Clock skew: `|timestamp - Clock::get()?.unix_timestamp| <= MAX_CLOCK_SKEW_SECS`.
  - Effects: writes `ProofRecord` (including `commitment_level` observed via RPC when confirming the transaction); updates `AggregatorState.last_seq = seq`; updates `range_state.last_end_slot = end_slot`; emits event (with `ds_hash`); increments `ValidatorRecord.num_accepts` for `submitted_by` if registered and `status=Active`.

- `update_config(params: { aggregator_pubkey: Option<Pubkey>, paused: Option<bool> })`
  - Accounts: `admin (signer)`, `config (PDA)`.
  - Effects: updates provided fields; emits `ConfigUpdated { aggregator_pubkey?, paused? }`.

- `unlock_validator()`
  - Accounts: `validator (signer)`, `config`, `validator_record (PDA)`, `validator_escrow (PDA)`, `validator_ata`, `token_program`.
  - Effects: transfers exactly 1 `$zKSL` from escrow back to validator; sets `status=Unlocked`.

- Events:
  - `ValidatorRegistered { validator_pubkey: Pubkey, escrow: Pubkey, timestamp: i64 }`
  - `ProofAnchored { artifact_id: [u8;16], proof_hash: [u8;32], start_slot: u64, end_slot: u64, submitted_by: Pubkey, timestamp: i64, seq: u64, ds_hash: [u8;32] }`
  - `ValidatorUnlocked { validator_pubkey: Pubkey, timestamp: i64 }`
  - `ConfigUpdated { aggregator_pubkey: Option<Pubkey>, paused: Option<bool>, timestamp: i64 }`
  - `Equivocation { range_start: u64, range_end: u64, signer: Pubkey, conflicting_hashes: [[u8;32];2] }` (Phase 2)

---

#### 21) Program Error Codes (normative)
- `6000` InvalidMint
- `6001` InvalidLockAmount
- `6002` AlreadyRegistered
- `6003` NotRegistered
- `6004` EscrowMismatch
- `6005` InvalidSignature
- `6006` AggregatorMismatch
- `6007` ProofAlreadyAnchored
- `6008` StatusNotActive
- `6009` MathOverflow
- `6010` Paused
- `6011` Unauthorized
- `6012` NonMonotonicSeq
 - `6013` RangeOverlap
 - `6014` ClockSkew
 - `6015` BadEd25519Order
 - `6016` BadDomainSeparation
 - `6017` InsufficientBudget

Errors SHALL be surfaced by the CLI with human-readable messages and original program error code.

---

#### 22) Off-chain HTTP APIs (optional orchestrator)
- Base URL (local): `http://localhost:8080`
- `GET /health` → `{ status: "ok", version }`
- `POST /artifact` → body = canonical artifact JSON; returns `{ artifact_id, proof_hash }` (stores to disk/DB).
 - `POST /anchor` → body = `{ artifact_id }`; server computes `proof_hash`, builds `DS` from (`chain_id`, `program_id`, `proof_hash`, `start_slot`, `end_slot`, `seq`), signs `DS`, and submits `anchor_proof` with `ds_hash`; returns `{ aggregator_signature, ds_hash, transaction_id }`.
- `GET /proof/:artifact_id` → returns full artifact and on-chain status.
- `GET /validator/:pubkey` → returns `ValidatorRecord` projection.

Notes:
- All endpoints MUST be idempotent with `Idempotency-Key` header; server stores last response keyed by header for 24h.
 - Error schema: `{"error": {"code": <string>, "message": <string>, "details": <object|null>}}`; HTTP status mirrors error class; codes map to Section 21 error names where applicable.

---

#### 23) Artifact Canonicalization and Cryptography (normative)
- Canonical JSON: JCS (RFC 8785). Keys sorted lexicographically, UTF-8, no insignificant whitespace, integers as base-10 without leading zeros.
- `proof_hash`: `BLAKE3-256( canonical_json_bytes )` → 32 bytes. Represented as hex lowercase for human I/O; on-chain stored as `[u8;32]`.
- `aggregator_signature`: ed25519 over the domain-separated message `DS`, where `DS = "zKSL/anchor/v1" || chain_id || program_id || proof_hash || start_slot || end_slot || seq` (all integers little-endian). `DS` begins with the exact 14-byte ASCII literal `zKSL/anchor/v1`. Store `ds_hash = blake3(DS)` alongside the record.
- Aggregator keypair:
  - Curve: ed25519.
  - Storage: file-based keystore with `chmod 600`; env `AGGREGATOR_KEYPAIR_PATH`.
  - Rotation: update `Config.aggregator_pubkey` via program upgrade/governance (out of scope in MVP).
 - Serialization elsewhere:
   - On-chain accounts and instruction data use Anchor (Borsh) encoding; integers are little-endian; fixed-size byte arrays for hashes/roots.
   - UUID `artifact_id` is stored as 16 raw bytes in network byte order.
 - Deterministic constants:
   - `MAX_SLOTS_PER_ARTIFACT = 2048`
   - `MAX_ARTIFACT_SIZE_BYTES = 512 * 1024` (512 KiB canonical JSON)
   - `MAX_CLOCK_SKEW_SECS = 120`

---

#### 24) CLI and Binaries (normative)
- Binary name(s): `zksl` (Unix), `zksl.exe` (Windows).
- Commands:
  - `zksl register --keypair <PATH> --mint <MINT> [--rpc-url <URL>] [--cluster localnet|devnet|testnet]`
  - `zksl prove --input <STATE_SNAPSHOT|TX_LOG> --out <ARTIFACT_PATH>`
  - `zksl anchor --artifact <ARTIFACT_PATH> --keypair <AGG_KEY>`
  - `zksl status --validator <PUBKEY>`
  - `zksl unlock --keypair <PATH>`
- Global flags: `--json`, `--quiet`, `--log-level trace|debug|info|warn|error`.
- Exit codes:
  - `0` success
  - `10` invalid arguments
  - `11` IO/file error
  - `12` network/RPC error
  - `13` program error (includes on-chain error codes)
  - `14` signature/crypto error
  - `15` canonicalization error
- Logging:
  - Default human-readable; `--json` emits structured logs with fields: `timestamp`, `level`, `msg`, `module`, `ctx`.

---

#### 25) Environment Variables (normative)
- Common:
  - `RPC_URL` default `http://localhost:8899`
  - `WS_URL` default `ws://localhost:8900`
  - `PROGRAM_ID_VALIDATOR_LOCK` program ID string
  - `ZKSL_MINT` token mint ID string (Mainnet: `9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump`)
  - `MIN_FINALITY_COMMITMENT` one of `processed|confirmed|finalized` (default `finalized`)
  - `CHAIN_ID` u64 (required) — must match on-chain `Config.chain_id` for DS
- Prover/Aggregator:
  - `ARTIFACT_DIR` default `./data/artifacts`
  - `AGGREGATOR_KEYPAIR_PATH` default `./keys/aggregator.json`
- Orchestrator:
  - `PORT` default `8080`
  - Reads `PROGRAM_ID_VALIDATOR_LOCK` from config to construct DS consistently with on-chain state
- Indexer:
  - `DATABASE_URL` Postgres connection string
  - `REDIS_URL` Redis connection string

All envs SHALL be documented in `.env.example` with defaults.

---

#### 26) Docker Compose (normative)
- Services (images pinned by digest in actual file):
  - `solana` → runs `solana-test-validator` with ledger volume, ports `8899:8899`, `8900:8900`.
  - `postgres` → Postgres 15.x; port `5432:5432`; volume `pgdata`.
  - `redis` → Redis 7.2; port `6379:6379`.
  - `prover` → Rust image; mounts `ARTIFACT_DIR`; depends on `solana`.
  - `orchestrator` → Node 20; exposes `8080`.
  - `indexer` → Node or Rust; depends on `postgres` and `solana`.
  - `prometheus` and `grafana` → optional observability; mapped ports `9090`, `3000`.
- Volumes: `ledger/`, `pgdata/`, `artifacts/`, `grafana/` (persist dashboards).
- Networks: single bridge network for service discovery.
 - Healthchecks (must pass or container is unhealthy):
  - `postgres`: `pg_isready`
  - `redis`: `redis-cli ping`
  - `orchestrator`: `GET /health` returns `{"status":"ok"}`
  - `indexer`: internal `/health` endpoint
 - Resource limits (dev defaults): CPU `1.0`, memory `512Mi` per service (tune in perf testing).
 - Compute budget guardrail: transactions submitted by orchestrator MUST include a ComputeBudget instruction with requested units ≥ 200_000; otherwise orchestrator rejects with `InsufficientBudget` and does not submit.

---

#### 27) Testing and Acceptance (normative)
- Unit tests:
  - On-chain: Anchor tests for each instruction, asserting account state and error codes.
  - Prover: deterministic artifact generation given fixed input.
- Integration test (happy-path):
  - Script steps: faucet → register → prove → anchor → status → unlock.
  - Assertions: escrow holds 1 token; `ValidatorRecord.status==Active` then `Unlocked`; `ProofRecord` exists with exact bytes; CLI exit code `0`.
- Negative tests:
  - Mismatched mint, wrong lock amount, duplicate proof, invalid signature, aggregator mismatch, unlock when not active.
- Reproducibility:
  - CI runs on clean containers; artifacts’ `proof_hash` and account sizes expected values are asserted.
 - Additional tests (security hardening):
  - Cross-chain replay KAT: identical `proof_hash` with different `program_id` MUST fail due to DS.
  - Instruction-order fuzz: multiple ed25519 syscalls present MUST be rejected unless exact preflight matches DS and index.
  - Reorg simulation: indexer watches commitment; on rollback, remove ProofRecord and restore `RangeState`.
  - Overlap denial: anchoring overlapping ranges MUST fail with `RangeOverlap`.
  - Sequencing: gaps or non-monotonic `seq` MUST fail with `NonMonotonicSeq`.
  - Clock skew beyond threshold MUST fail with `ClockSkew`.

---

#### 28) Reproducibility Checklist (operator)
- Use provided Docker Compose with pinned digests.
- Use lockfiles: `Cargo.lock`, `pnpm-lock.yaml` committed and `--frozen-lockfile` used.
- Confirm versions: `solana --version`, `anchor --version`, `rustc --version`, `node --version` match matrix.
- Ensure `.env` matches `.env.example` required variables.
- Run one-command bootstrap: `docker compose up -d` then `./scripts/dev_bootstrap.sh`.
- Verify IDs: program ID in `Anchor.toml` equals on-chain deployed ID; mint matches `ZKSL_MINT`.

---

#### 29) Product Requirements (PRD) and Network Modes
- Product goals:
  - Provide a provably anchored execution pathway with validator registration via `$zKSL` lock.
  - Operate reliably on Solana devnet and testnet with public RPCs and self-hosted RPC.
  - Expose stable APIs and CLI for validators and provers.
- Personas:
  - Validator operator, Prover operator, Integrator (dApp/infra), Researcher.
- Network modes:
  - `localnet` (default): Dockerized `solana-test-validator`, full stack.
  - `devnet`: deployment with devnet program IDs, faucet-controlled mint.
  - `testnet`: deployment with restricted access controls and monitored SLAs.
- SLAs (devnet/testnet):
  - Proof anchoring API: 99.5% 24h availability (excluding network outages).
  - Anchoring latency p95: ≤ 3s from submit to on-chain confirmation under nominal load.
 - Finality policy:
   - Indexer/UI MUST consider anchors final only at RPC commitment `finalized`; until then display `tentative`.
   - On reorg detection, rollback latest non-final anchors and recompute `RangeState`.

---

#### 30) Token and Mint Lifecycle
- `$zKSL` mint:
  - Pre-existing pump.fun SPL mint referenced by `ZKSL_MINT` (mainnet: `9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump`). `decimals` and supply are defined on-chain; mint/freeze authority is presumed revoked.
- Distribution (devnet/testnet):
  - No faucet on mainnet. For devnet/localnet demos, use a separate test mint; production deployments MUST reference the live mint via `ZKSL_MINT`.
- Validator lock rules:
  - Exactly 1 token must reside in `ValidatorEscrow` PDA while active (i.e., `10^decimals` base units of the live mint).
  - Unlock conditions: `status=Active`, no pending slashing (MVP: none), optional unbonding delay.
- Accounting:
  - Indexer tracks circulating vs locked supply; dashboard displays gauge and time-series.

---

#### 31) Governance, Upgrades, and Aggregator Set
- Program upgradeability:
  - Governed via an upgrade authority (multisig M-of-N) restricted to non-breaking changes; IDL versioning follows semver.
  - Emergency pause: optional boolean flag in `Config` to reject new registrations/anchors.
- Aggregator set:
  - MVP: single aggregator key in `Config`.
  - Phase 2: threshold policy `t-of-n` aggregator signatures. On-chain instruction accepts a compact bitmap and aggregated signature (off-chain aggregation), and verifies `>= t` signatures via multiple ed25519 syscalls.
- Policy rotation:
  - Upgrade path: `update_config` instruction guarded by governance; emits `ConfigUpdated` event.
  - Non-halt rotation: fields `next_aggregator_pubkey` and `activation_seq` allow key roll; accept signatures from either key for `seq >= activation_seq`.

---

#### 32) Activation, Unlock, and Slashing Policies
- Activation:
  - Registration becomes active immediately upon successful escrow transfer.
- Unlock:
  - Optional `UNBOND_SECONDS` (default 0 in MVP). If >0, `unlock_validator` starts a timer; withdrawal allowed after expiry.
- Slashing (Phase 2+):
  - Misbehavior types: invalid proof attestation, double-sign attestations, liveness failure beyond window.
  - Evidence submission: `submit_slash_evidence` instruction referencing `ProofRecord` and signatures.
  - Penalty: partial or full burn of locked token; configurable by governance.

---

#### 33) Data Availability Storage and Sampling
- Storage backends:
  - Local filesystem for MVP; S3/MinIO for devnet/testnet (`S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`).
- Object layout:
  - `artifacts/<yyyy>/<mm>/<dd>/<artifact_id>.json` (canonical JSON)
  - `artifacts/<yyyy>/<mm>/<dd>/<artifact_id>.bin` (optional binary pack)
- Integrity:
  - Object ETag and `proof_hash` MUST match; uploader rejects on mismatch.
- Erasure coding (optional demo):
  - `k=20, m=10` shards with `reed-solomon-erasure`; random sampling of `q` shards to validate availability.

---

#### 34) Indexer Schema and Queries
- Schema (Postgres):
  - `validators(pubkey TEXT PRIMARY KEY, status TEXT NOT NULL CHECK (status IN ('Active','Unlocked')), escrow TEXT NOT NULL, lock_ts TIMESTAMPTZ NOT NULL, unlock_ts TIMESTAMPTZ, num_accepts BIGINT NOT NULL DEFAULT 0, last_seen TIMESTAMPTZ)`
  - `proofs(artifact_id UUID NOT NULL UNIQUE, start_slot BIGINT NOT NULL, end_slot BIGINT NOT NULL, proof_hash BYTEA NOT NULL CHECK (octet_length(proof_hash)=32), ds_hash BYTEA NOT NULL CHECK (octet_length(ds_hash)=32), artifact_len INT NOT NULL CHECK (artifact_len BETWEEN 0 AND 524288), state_root_before BYTEA NOT NULL CHECK (octet_length(state_root_before)=32), state_root_after BYTEA NOT NULL CHECK (octet_length(state_root_after)=32), submitted_by TEXT NOT NULL, aggregator_pubkey TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL, seq BIGINT NOT NULL, commitment_level SMALLINT NOT NULL, da_params BYTEA, txid TEXT NOT NULL UNIQUE, PRIMARY KEY (proof_hash, seq))`
  - `metrics(name, ts, value)`
- Indices:
  - `proofs(proof_hash)`, `proofs(ts)`, `validators(status)`, `validators(last_seen)`
  - `proofs(ds_hash)`
  - `proofs_range_idx (start_slot, end_slot)`
 - Checks:
  - `CHECK (commitment_level IN (0,1,2))`
- Queries:
  - Latest proofs: `SELECT * FROM proofs ORDER BY ts DESC LIMIT 50;`
  - Validator live set: `SELECT * FROM validators WHERE status='Active';`
  - Locked supply: `SELECT COUNT(*) FROM validators WHERE status='Active';`

---

#### 35) Observability and SRE Runbooks
- Metrics:
  - Anchoring rate, success/failure counts, ed25519 verification failures, RPC latency percentiles, queue depths.
- Alerts:
  - No anchors for >10m, RPC error rate >5%, Redis saturation >80%, DB lag > 30s.
- Runbooks:
  - RPC flaps: fail over to backup RPC; drain queues; re-submit pending anchors.
  - DB outage: switch to read-only mode; queue writes; restore from latest snapshot.
  - Key compromise: rotate aggregator key; update `Config`; invalidate old signatures.

---

#### 36) Security, Threat Model, and Key Management
- Threats:
  - Malicious prover submits forged artifacts; mitigated by signature policy and future thresholding.
  - Replay attacks; mitigated by DS binding (chain_id, program_id, proof_hash, start_slot, end_slot, seq) and `seq` monotonicity with `RangeState`.
  - DoS on orchestrator; mitigated by rate limits and circuit breakers.
- Key management:
  - Aggregator keys in filesystem keystore with process-level permission model; optional HSM support (YubiHSM or cloud KMS) via plugin.
  - Validations: startup checks ensure keys readable and match `Config.aggregator_pubkey`.

---

#### 37) Release, Versioning, and Migrations
- Versioning:
  - Semver across program (IDL), CLI, prover, indexer. Cross-component compatibility matrix maintained in README.
- Migrations:
  - DB migrations via `sqlx` or `knex`; versioned scripts.
  - Program migrations: new accounts add fields via reserved bytes; breaking changes require new PDAs and a migration tool.
- Release artifacts:
  - Docker images with digests; GitHub releases with changelogs and SBOMs; checksums for binaries.

---

#### 38) Deployment Steps (Devnet/Testnet)
1. Provision infrastructure: Postgres, Redis, S3/MinIO, Prometheus, Grafana.
2. Deploy `validator_lock` program with Anchor; record program ID.
3. Set `ZKSL_MINT` to the live pump.fun mint `9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump` (mainnet). For devnet/localnet demos, set `ZKSL_MINT` to a test mint.
4. Configure `.env` for all services (program IDs, mint, RPC URLs).
5. Run indexer, prover, orchestrator with Docker Compose; validate health endpoints.
6. Register a validator via CLI; confirm escrow and `ValidatorRecord`.
7. Produce and anchor a proof artifact; check indexer and dashboard.
8. Execute unlock; confirm token return and state update.

---

#### 39) Onboarding Flows (Validator and Prover)
- Validator:
  - Install CLI; create wallet; (mainnet) acquire 1 `$zKSL` from the live pump.fun mint; (devnet/localnet) request faucet for a test mint; run `zksl register`; monitor status; operate.
- Prover:
  - Install prover; configure inputs; run service; monitor queue; anchor via orchestrator or CLI.

---

#### 40) API Rate Limits and Access Control
- Rate limits (default): `POST /anchor` 10 req/min/IP; `POST /artifact` 60 req/min/IP.
- Access control:
  - API keys for orchestrator (devnet/testnet); keys stored hashed in DB; rotated monthly.
- Circuit breakers:
  - Temporarily reject anchors if RPC backlog > threshold or DB lag exceeds SLA.

---

#### 41) Performance Targets and Benchmarks
- Targets:
  - Anchoring throughput: ≥ 10 proofs/min sustained.
  - p95 end-to-end anchoring latency: ≤ 3s; p99 ≤ 6s on devnet.
- Benchmarks:
  - Load generator submits artifacts with fixed sizes; capture RPC/DB latencies; publish dashboards.

---

#### 42) Appendices: Canonical Examples and Templates
- `.env.example` keys with defaults.
- Canonical `Config` JSON and expected account sizes.
- Sample artifact JSON with canonical serialization and computed `proof_hash`.
- Docker Compose template with image digests placeholders.
- CLI session transcripts (register, prove, anchor, status, unlock) with example outputs.

---

#### 43) Code Quality and Testing Policy (world-class, normative)
- Principles:
  - Zero undefined behavior. Zero data races. Zero panics in library code. Zero unchecked results.
  - No unsafe code unless proven necessary and approved; all unsafe blocks require RFC and formal justification.
  - No dead code, no unused deps, no warnings in any build target; CI fails on any warning.
  - Deterministic builds, hermetic tests, reproducible benchmarks.

- Rust (program/prover/indexer):
  - Crate attributes (root):
    - `#![forbid(unsafe_code)]`
    - `#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]`
    - `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]`
    - `#![deny(missing_docs, rustdoc::broken_intra_doc_links)]`
  - `clippy.toml`:
    - `msrv = "1.80"`
    - `warn-on-all-wildcard-imports = true`
    - `cognitive-complexity-threshold = 10`
  - Enforce explicit `#[must_use]` on public returns that carry state or results; annotate domain types accordingly.
  - Prohibit `anyhow` in on-chain crates; use precise error enums with `#[error(...)]`.
  - Feature flags minimal; forbid default-features leakage.

- TypeScript/Node (CLI/orchestrator):
  - `tsconfig.json`: `"strict": true`, `"noImplicitAny": true`, `"exactOptionalPropertyTypes": true`, `"noUncheckedIndexedAccess": true`, `"noFallthroughCasesInSwitch": true`, `"useUnknownInCatchVariables": true`.
  - ESLint: `@typescript-eslint/recommended`, `eslint:all` with explicit disables; no `any`, no `ts-ignore` without `@rule-justification` comment.
  - Prettier pinned; no formatting diffs in CI.

- Security and secrets:
  - Forbid printing secrets; redaction middleware required; CI scans with `gitleaks`.
  - Keys loaded with least privilege; process runs as non-root in Docker; seccomp and read-only FS where possible.

- Testing taxonomy:
  - Unit tests: per-module, exhaustive edge cases, no network IO.
  - KATs (Known-Answer Tests): canonical inputs/outputs for hashing, canonicalization, signature verification, PDA derivation, and account sizing.
  - Property-based tests: use `proptest` (Rust) and `fast-check` (TS) for invariants (idempotence of canonicalization, commutativity where applicable, monotonic `seq`).
  - Fuzzing: `cargo fuzz` with libFuzzer targets for artifact parser, canonicalizer, and ed25519 verifier integration.
  - Golden tests: snapshot JSON for IDL, artifact canonical forms, CLI outputs; snapshots versioned and reviewed.
  - Integration tests: end-to-end flows (register→prove→anchor→status→unlock) with ephemeral localnet.
  - Benchmarks: `criterion` (Rust) for hashing, serialization, and DB ingest; TS benchmarks via `benchmark.js` or `node:diagnostics_channel` with custom harness.
  - Mutation testing: `mutagen` (Rust) or `cargo-mutants`; TS via `stryker` with thresholds.

- Coverage thresholds (CI gating):
  - Rust: `grcov` + `llvm-cov` line coverage ≥ 90%, branch ≥ 80%, functions ≥ 95%.
  - TS: `nyc` coverage lines ≥ 90%, branches ≥ 80%.
  - Fuzz: minimum 1h corpus growth weekly in scheduled CI; crashers block release.

- CI gates (all must pass):
  - Format: `cargo fmt --check`, `pnpm prettier:check`.
  - Lint: `cargo clippy --all-targets -- -D warnings -W clippy::pedantic`, `pnpm lint`.
  - Build: release builds for all crates and CLI.
  - Test: unit + integration; deterministic seeds logged.
  - Coverage: thresholds enforced.
  - Security: `cargo deny check`, `npm audit --production`, `gitleaks`, container image scan (Trivy/Grype).
  - SBOM: generate and attach to artifacts (Syft/CycloneDX).

- Code review policy:
  - Two approvals required; one with security focus. No self-merge. Require green CI.
  - Every unsafe block (if any) must include a formal invariants comment and dedicated tests.
  - Performance-sensitive changes must include before/after benchmarks and flamegraphs.

- Performance engineering:
  - Require allocations profiling for hot paths; avoid heap in on-chain code paths; prefer `Vec::with_capacity`.
  - Enforce no `to_string()` in critical loops; use borrowed forms.
  - Database: prepared statements, batched writes; p95 targets in Section 41.

- Documentation:
  - Public items must have rustdoc/jsdoc with examples; `cargo doc` and typedoc generated in CI.
  - Architecture decision records (ADRs) for changes to protocols or security posture.

- Release blocks:
  - Any warning, failing test, or coverage regression blocks release.
  - Any `TODO`/`FIXME` blocks release; forbid merging with such tags in code.

