# zkSealevel POC Execution Plan (Devnet)

A byte-precise, production-grade plan to take zkSealevel from concept to a working, demonstrable POC on Solana Devnet with real cryptography and verifiable proofs, matching the Whitepaper draft.

---

## 1) Objectives and Scope

- Build an end-to-end, locally runnable POC that connects to Solana Devnet and anchors proof records on-chain using the `validator_lock` Anchor program.
- Use real cryptography throughout: Blake3, Ed25519, and a STARK prover (initial minimal AIR), with deterministic canonicalization.
- Enforce byte-precise protocol rules for Domain Separation (DS), instruction ordering, PDAs, Borsh encodings, account sizes, error semantics.
- Provide an operational path: deploy on devnet, run services, prove, anchor, index, and visualize status.

Non-goals for the POC:
- Full zk-BPF AIR for the entire Sealevel VM (this is the long-term target). The POC will initially prove a constrained computation and wire the proof artifact into the same anchoring pipeline, so the end-to-end path is real and verifiable while the AIR expands incrementally.

---

## 2) End-to-End System Flow (Devnet)

1. Prover creates a canonical proof artifact (JSON) for a given slot range and state roots; computes `proof_hash = blake3(canonical_json)`; builds 110-byte DS message; signs DS with Ed25519 aggregator key.
2. Orchestrator validates/canonicalizes artifacts, verifies DS against the aggregator key policy and chain_id, and submits an on-chain `anchor_proof` transaction with ComputeBudget + Ed25519 + Anchor ix ordering.
3. On-chain program (`validator_lock`) enforces DS integrity, Ed25519 preflight, sequence and slot-range monotonicity, and writes a `ProofRecord` PDA.
4. Indexer mirrors on-chain accounts into Postgres; commitment levels are reconciled to confirmed/finalized.
5. CLI/UI (demo) queries orchestrator and DB to display the proof lifecycle and validator registry.

---

## 3) Components, Ownership, and Readiness

- On-chain: `programs/validator_lock` (Anchor, Rust) — already implements: config, validator lock/unlock, anchor_proof with strict preflight and DS checks. Action: deploy to devnet, align IDs.
- Orchestrator: `orchestrator/src/server.ts` — artifact handling, DS build/submit, error mapping. Action: wire prover verification hook.
- Indexer: `indexer/src/index.ts` — program account decode, upsert to Postgres, commitment reconciliation. Action: confirm devnet WS/poll resilience.
- Prover: `prover/src/main.rs` — canonical JSON, `proof_hash`, DS hash, Ed25519 signature. Action: add minimal STARK proof of a constrained computation.
- DB/Migrations: `migrations/*.sql` — validators, proofs, indexer_state schema ready. Action: apply migrations on local Postgres.
- CLI (demo): mock-first showcase. Action: keep as-is for UX; add real-path commands (optional).

---

## 4) Byte-Precise Protocol Contracts (MUST match Whitepaper + Program)

### 4.1 Canonical Artifact (JSON)
- Deterministic, JCS-like canonicalization: map keys sorted lexicographically, omit undefined, serialize numbers/strings/arrays/objects without extra whitespace.
- Minimal required fields:
  - `artifact_id: string (uuid-v4)`
  - `start_slot: u64` (number)
  - `end_slot: u64` (number, ≥ start_slot; window ≤ 2048)
  - `state_root_before: hex(32 bytes)`
  - `state_root_after:  hex(32 bytes)`
- `proof_hash`: `blake3(canonical_json_bytes)` → 32 bytes; hex-encoded when exchanged in JSON.

### 4.2 Domain Separation (DS) Message (exactly 110 bytes)
- Prefix (14): ASCII `"zKSL/anchor/v1"`
- `chain_id`: u64 LE (8)
- `program_id`: 32 (raw program pubkey bytes)
- `proof_hash`: 32 (raw bytes)
- `start_slot`: u64 LE (8)
- `end_slot`: u64 LE (8)
- `seq`: u64 LE (8)
- Total: 14 + 8 + 32 + 32 + 8 + 8 + 8 = 110 bytes.
- `ds_hash = blake3(DS)` (32 bytes) used for integrity checks on-chain.

### 4.3 Ed25519 Preflight Instruction (must immediately precede `anchor_proof`)
- Exactly 1 Ed25519 instruction in the transaction.
- ComputeBudget `SetComputeUnitLimit(units ≥ 200,000)` must appear in the transaction (program verifies presence).
- Ed25519 data layout (single signature case):
  - `num` (u8) = 1
  - Offsets/lengths: `sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix` as little-endian u16
  - For in-instruction references: `sig_ix = pk_ix = msg_ix = 0xFFFF`
  - Bounds must be valid; program checks that:
    - public key bytes equal the allowed aggregator pubkey for the given seq
    - message bytes equal the 110-byte DS

### 4.4 Anchor Instruction Encoding (Borsh payload + discriminator)
- Discriminator: first 8 bytes = `sha256("global:anchor_proof")[0..8]`
- Payload field order and sizes:
  1) `artifact_id: [u8; 16]`
  2) `start_slot: u64 LE`
  3) `end_slot: u64 LE`
  4) `proof_hash: [u8; 32]`
  5) `artifact_len: u32 LE`
  6) `state_root_before: [u8; 32]`
  7) `state_root_after:  [u8; 32]`
  8) `aggregator_pubkey: [u8; 32]` (ed25519)
  9) `timestamp: i64 LE` (seconds)
  10) `seq: u64 LE`
  11) `ds_hash: [u8; 32]`

### 4.5 PDAs, Seeds, and Account Sizes (fixed)
- Config PDA: seeds `[b"zksl", b"config"]`
- AggregatorState PDA: `[b"zksl", b"aggregator"]` (fields: `aggregator_pubkey: [32]`, `last_seq: u64`, reserved[86])
- RangeState PDA: `[b"zksl", b"range"]` (`last_end_slot: u64`, reserved[120])
- ProofRecord PDA: `[b"zksl", b"proof", proof_hash[32], seq[u64 LE]]`
- ValidatorRecord PDA: `[b"zksl", b"validator", validator_pubkey[32]]`
- Account sizes (bytes) — must match program tests:
  - `Config::SIZE = 168`
  - `ValidatorRecord::SIZE = 136`
  - `ProofRecord::SIZE = 262`

### 4.6 Validator Lock & Mint Rules
- Exactly 1 `zKSL` token locked to activate: transfer-checked by mint decimals; escrow ATA owned by escrow PDA.
- Unlock returns exactly 1 token from escrow ATA back to validator ATA; status moves to Unlocked.

### 4.7 Sequence, Range, and Time Invariants
- `seq` is global, strictly monotonic across key rotations (AggregatorState.last_seq).
- Slot range contiguous: `start_slot == last_end_slot + 1` (first range must start at 1). Window ≤ 2048.
- Clock skew bound: `|now - timestamp| ≤ MAX_CLOCK_SKEW_SECS (120s)`.

### 4.8 Chain ID and Aggregator Key Rotation
- `chain_id` in DS must equal on-chain config `chain_id`.
- Allowed aggregator key for `seq`: `seq < activation_seq ? aggregator_pubkey : next_aggregator_pubkey`.

### 4.9 Error Semantics (subset)
- `BadEd25519Order`, `BadDomainSeparation`, `NonMonotonicSeq`, `RangeOverlap`, `ClockSkew`, `AggregatorMismatch`, `InvalidMint`, `InsufficientBudget` — mapped to 4xx errors at Orchestrator.

---

## 5) Prover Roadmap (STARK) — Minimal yet Real

Target library: **Winterfell (Rust)** for a transparent STARK with Blake3 as the hash primitive.

### 5.1 Phase A (Minimal AIR to Prove a Constrained Transition)
- Define a small AIR that proves a constraint on the relation between `state_root_before`, `state_root_after`, and the slot window:
  - Example: `state_root_after = Blake3( state_root_before || LE(start_slot) || LE(end_slot) || DS_PREFIX )` evaluated over a trace, with constraints that bind the digest computation steps (sponge/hash component in AIR) and an accumulator over lanes.
  - Expose public inputs: `state_root_before`, `state_root_after`, `start_slot`, `end_slot`, `proof_hash`.
  - Generate proof bytes (~few KB) with security params suitable for POC.
- Output: proof artifact extended with `stark_proof` (hex/base64) and `public_inputs` JSON.

### 5.2 Phase B (Streaming IVC Skeleton)
- Prototype a streaming folding loop over micro-batches:
  - Each micro-batch: 64–256 logical steps; fold x N; final proof carries public inputs for the full window.
- Keep constraints simple initially (hash chain); defer full zk-BPF AIR to the next phases.

### 5.3 Integration Contract
- The **on-chain program remains unchanged**: it anchors only the `ProofRecord` derived from the `proof_hash` + DS.
- The Orchestrator verifies the STARK proof off-chain against `public_inputs` before submitting `anchor_proof` (reject if invalid).
- Store the STARK proof alongside the canonical artifact in `ARTIFACT_DIR` for auditability and demo.

---

## 6) Orchestrator Enhancements

- Add `POST /prove` (off-chain):
  - Accept minimal inputs (slot range, pre/post roots).
  - Run Prover (Winterfell) to produce `stark_proof` and `public_inputs`.
  - Construct canonical artifact, compute `proof_hash`.
- Extend `POST /anchor`:
  - Optionally require `stark_proof` and verify it before anchoring.
  - Preserve current DS construction and Ed25519 signature flow.
- Observability:
  - Structured logs for proof generation duration, verify result, tx signature.
  - Prometheus counters (optional).

---

## 7) On-Chain Program (Anchor) — Devnet Deployment Plan

1. Update `declare_id!` with the actual devnet deployed program ID.
2. Build & deploy with Anchor:
   ```bash
   anchor build
   anchor keys list
   anchor deploy --provider.cluster devnet
   ```
3. Initialize `Config` via an admin script:
   - Create/mint `zKSL` SPL token (decimals = 9 recommended) on devnet.
   - Choose admin keypair, aggregator & next_aggregator pubkeys.
   - `initialize` with `{ zksl_mint, admin, aggregator_pubkey, next_aggregator_pubkey, activation_seq, chain_id }`.
4. Fund a validator keypair on devnet; create ATA for zKSL; mint exactly 1 zKSL to validator; run `register_validator`.
5. Rotate aggregator key by calling `update_config` with new `next_aggregator_pubkey` and `activation_seq` (for testing).

---

## 8) Indexer — Devnet Readiness

- Use websockets with fallback polling every 20s.
- Apply migrations and set `DATABASE_URL`.
- Confirm decoding of `ProofRecord` and `ValidatorRecord` matches account sizes and field order.
- Reconcile commitment levels via `getSignatureStatuses`.

---

## 9) Database & Migrations

Apply, in order:
```sql
001_init.sql
002_indexer_state.sql
003_indexer_cursor.sql
004_indexer_last_signature.sql
```
- Verify constraints: `octet_length` checks for 32-byte fields; `commitment_level in (0,1,2)`; range index on `(start_slot, end_slot)`.

---

## 10) Dev & Ops Runbooks

### 10.1 Environment
```bash
# .env (example)
PORT=8080
RPC_URL=https://api.devnet.solana.com
PROGRAM_ID_VALIDATOR_LOCK=<DEVNET_PROGRAM_ID>
CHAIN_ID=103
AGGREGATOR_KEYPAIR_PATH=./keys/aggregator.json
ARTIFACT_DIR=./orchestrator/data/artifacts
DATABASE_URL=postgres://postgres:postgres@localhost:5432/zksl
MIN_FINALITY_COMMITMENT=finalized
```

### 10.2 Keys & Mint
- Generate `aggregator.json` with `{ secretKey: <64-byte hex seed+key> }`.
- Create SPL mint `zKSL`; mint exactly 1 token to validator’s ATA.

### 10.3 Start Services
```bash
# Orchestrator
pnpm ts-node orchestrator/src/server.ts  # or build+node dist

# Indexer
pnpm ts-node indexer/src/index.ts

# Prover (reference)
cargo run -p prover -- --input artifact.json --out proof.json --agg-key ./keys/aggregator.json --chain_id 103 --program_id <DEVNET_PROGRAM_ID> --seq 1
```

### 10.4 Anchor a Proof (end-to-end)
```bash
# Build canonical artifact (or POST /prove for integrated path)
curl -s -X POST http://localhost:8080/artifact \
  -H 'Idempotency-Key: test-1' \
  -H 'Content-Type: application/json' \
  -d '{
    "artifact_id": "00000000-0000-4000-8000-000000000001",
    "start_slot": 1,
    "end_slot": 64,
    "state_root_before": "<64 hex>",
    "state_root_after":  "<64 hex>"
  }'

# Anchor it
curl -s -X POST http://localhost:8080/anchor \
  -H 'Idempotency-Key: test-2' \
  -H 'Content-Type: application/json' \
  -d '{ "artifact_id": "<artifact_id_from_previous>" }'
```

---

## 11) Acceptance Criteria

- `initialize` executed on devnet with correct config; `register_validator` succeeds; escrow holds exactly one token.
- Orchestrator constructs DS=110B, signs DS, and submits `anchor_proof` with ComputeBudget + Ed25519 ordering. Transaction confirms.
- Program accepts only when all invariants pass; otherwise returns precise error codes.
- Indexer records a `ProofRecord` row with `commitment_level` ≥ confirmed and updates cursors.
- Prover produces a valid STARK proof for the minimal AIR; Orchestrator rejects anchoring if proof verification fails (Phase A, optional gate).

---

## 12) Risks & Mitigations

- Ed25519 instruction layout differences across SDK versions → Mitigate by constructing Ed25519 ix with `@solana/web3.js` helper and unit-testing against program parser.
- RPC rate limits on devnet → Add exponential backoff + WS fallback + small concurrency limits.
- STARK prover complexity → Start with minimal AIR; gate anchoring on prover verification only when ready; keep DS/Anchor path independent.
- Mint/decimals mismatch → Enforce via `has_one` and decimal-checked TransferChecked.

---

## 13) Planning Ethic (No Timelines)

To align with an under-promise and over-deliver ethic, this plan intentionally avoids timeline or scheduling commitments. Activities should be executed in the order that de-risks the system earliest (on-chain invariants → DS/Ed25519 correctness → off-chain verification → integration), with scope and sequencing decided by maintainers based on empirical readiness. Progress is measured by deterministic tests and conformance gates rather than dates.

---

## 14) Appendix — Exact Byte Layouts & Sizes

### 14.1 DS (Domain Separation) — 110 bytes
```
Offset  Size  Field
0      14     "zKSL/anchor/v1"
14     8      chain_id (u64 LE)
22     32     program_id (raw 32 bytes)
54     32     proof_hash (raw 32 bytes)
86     8      start_slot (u64 LE)
94     8      end_slot   (u64 LE)
102    8      seq        (u64 LE)
```
`ds_hash = blake3(DS)` (32 bytes)

### 14.2 Anchor Instruction Data
```
[8]  discriminator = sha256("global:anchor_proof")[0..8]
[16] artifact_id
[8]  start_slot (u64 LE)
[8]  end_slot (u64 LE)
[32] proof_hash
[4]  artifact_len (u32 LE)
[32] state_root_before
[32] state_root_after
[32] aggregator_pubkey
[8]  timestamp (i64 LE)
[8]  seq (u64 LE)
[32] ds_hash
```

### 14.3 PDA Seeds & Sizes
- Config: `[b"zksl", b"config"]`, `Config::SIZE = 168`
- AggregatorState: `[b"zksl", b"aggregator"]`, size = `32 + 8 + 86`
- RangeState: `[b"zksl", b"range"]`, size = `8 + 120`
- ProofRecord: `[b"zksl", b"proof", proof_hash, seq_le]`, size = 262
- ValidatorRecord: `[b"zksl", b"validator", validator_pubkey]`, size = 136

### 14.4 Ed25519 (Single-Signature) Offsets
- `num = 1`
- Offsets (u16 LE): `sig_off, sig_ix=0xFFFF, pk_off, pk_ix=0xFFFF, msg_off, msg_len, msg_ix=0xFFFF`
- Program checks:
  - exactly one Ed25519 ix in the transaction
  - it is immediately before `anchor_proof`
  - public key == allowed aggregator pubkey
  - message bytes == DS (110 bytes)

---

## 15) Whitepaper Mapping

- Validator Lock (1 token bond) → `register_validator` / `unlock_validator` with decimal-checked SPL transfers; `ValidatorRecord` and escrow PDA.
- Transparent STARKs & DS → DS prefix, chain binding, proof hashing, STARK prover off-chain verification (Phase A).
- Aggregator key rotation & seq monotonicity → enforced via `activation_seq`, `AggregatorState.last_seq`.
- Slot range & DA → range monotonicity enforced on-chain; DA params reserved; sampling planned for later.
- Economic security & Sybil resistance → lock requirement enforced on-chain; measurable `num_accepts` increments per anchored proof.

This plan is byte-precise and aligned with the Whitepaper and current code. It avoids timeline commitments and focuses on deterministic, verifiable contracts.

---

## 16) Determinism Policy (No Hidden Sources of Randomness)

- Artifact ID derivation (deterministic):
  - `artifact_id = uuid_v4_from_bytes( blake3(canonical_json)[0..16] )` — map first 16 bytes to UUID v4 by setting variant and version bits:
    - Set version nibble (byte 6 high nibble) to `0b0100`.
    - Set variant bits (byte 8 high bits) to `0b10xxxxxx`.
  - This ensures any identical artifact yields the same `artifact_id`.
- DS bytes, `ds_hash`, `proof_hash` are functionally deterministic given inputs.
- Timestamps:
  - Use `timestamp = floor(devnet_clock.unix_seconds)` read via `Clock` sysvar on-chain and mirrored off-chain for demo-validation; Orchestrator uses local time only to populate tx field but must be within skew bounds (≤ 120s).
- Orchestrator idempotency:
  - `Idempotency-Key` required on POSTs; stored for 24h; if repeated, returns identical response body and status.
- File layout deterministic:
  - `ARTIFACT_DIR/YYYY/MM/DD/{artifact_id}.json` — no random suffix; content is canonical JSON.
- No PRNG usage in critical paths. Unit tests seed any PRNG with fixed seeds.

---

## 17) Canonicalization Spec (Normative)

- Values:
  - `null` → `null`; `boolean` → `true|false`; `number` → decimal without trailing zeros or `+`; `string` → JSON-escaped; `array` → `[item1,item2,...]` (no spaces); `object` → `{k1:v1,k2:v2,...}` with keys sorted lexicographically ascending, skipping properties with `undefined`.
- Encoding:
  - UTF-8 bytes of the serialized string; no BOM.
- Hex fields:
  - `state_root_before`, `state_root_after` must be exactly 64 hex chars (lower/upper both accepted in input; stored canonicalized as lowercase in artifact JSON output).
- Example (minified):
  - `{"artifact_id":"00000000-0000-4000-8000-000000000001","end_slot":64,"start_slot":1,"state_root_after":"ab..","state_root_before":"cd.."}`

---

## 18) Orchestrator API Schemas (JSON)

- `POST /artifact` Request:
```json
{
  "artifact_id": "00000000-0000-4000-8000-000000000001",
  "start_slot": 1,
  "end_slot": 64,
  "state_root_before": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "state_root_after":  "89abcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
}
```
- Response 200:
```json
{
  "artifact_id": "00000000-0000-4000-8000-000000000001",
  "proof_hash": "aabbcc... (64 hex)"
}
```
- Errors: `400 BadRequest` with `{ error: { code, message, details } }`.

- `POST /anchor` Request:
```json
{ "artifact_id": "00000000-0000-4000-8000-000000000001" }
```
- Response 200:
```json
{
  "aggregator_signature": "<hex-64>",
  "ds_hash": "<hex-64>",
  "transaction_id": "<base58_sig>"
}
```
- Errors: `400` codes as mapped; `500` for `AnchorSubmitFailed`.

- `GET /proof/:artifact_id` Response 200:
```json
{ "artifact": { /* canonical fields */ }, "status": { "commitment_level": 2, "txid": "...", "seq": "1" } }
```

- `GET /validator/:pubkey` Response 200:
```json
{ "validator": { "pubkey": "...", "status": "Active", "escrow": "...", "lock_ts": "...", "num_accepts": "...", "last_seen": "..." } }
```

---

## 19) Transaction Construction (Deterministic & Verifiable)

- ComputeBudget program ix: `SetComputeUnitLimit({ units: 200_000 })`.
- Ed25519 ix: `Ed25519Program.createInstructionWithPublicKey({ publicKey: aggregator_pubkey, message: DS, signature })`.
- Anchor ix: `anchor_proof` with Borsh payload; PDAs derived exactly as in program.
- Order: `ComputeBudget → Ed25519 → anchor_proof`.
- Fee payer: aggregator keypair (same as Ed25519 signer) for simplicity.
- Recent blockhash: from `getLatestBlockhash`; `commitment = MIN_FINALITY_COMMITMENT`.

---

## 20) PDA Derivation Examples (Worked)

- Given `PROGRAM_ID = Val1dAt0rLock1111111111111111111111111111111` (devnet actual may differ):
  - `configPda = findProgramAddress(["zksl","config"])`
  - `aggregatorStatePda = findProgramAddress(["zksl","aggregator"])`
  - `rangeStatePda = findProgramAddress(["zksl","range"])`
  - `proofRecordPda = findProgramAddress(["zksl","proof", proof_hash32, seq_le8])`
  - `validatorRecordPda = findProgramAddress(["zksl","validator", submitted_by_pubkey])`
- Validate via `solana-keygen grind --starts-with` (optional) or programmatic check.

---

## 21) Versions & Reproducibility Matrix

- Solana CLI: `>= 1.18.0`
- Anchor CLI: `>= 0.29.0`
- Node.js: `>= 20.11.0`
- TypeScript: `~5.4.x`
- @solana/web3.js: `^1.91.0`
- Postgres: `>= 15`
- Rust: `>= 1.75`, Nightly optional for Winterfell
- Crates:
  - `blake3 = "^1.5"`
  - `ed25519-dalek = "^2.1"`
  - `winterfell = "^0.7"` (or latest stable)
- Locks:
  - Use `cargo update -p <crate>@<version>` pins; use `pnpm-lock.yaml` for Node reproducibility.

---

## 22) Build & Run Scripts (Deterministic)

- `scripts/dev_bootstrap.sh` (to be added): installs exact versions, verifies toolchains, applies migrations.
- `scripts/anchor_init.sh`: deploy + initialize `Config` with pinned parameters.
- `scripts/demo_anchor.sh`: crafts one artifact and anchors it end-to-end, then prints tx and DB row.

---

## 23) Test Plan (Unit, Integration, E2E)

- Unit (Orchestrator): canonicalization (golden vectors), DS builder (byte-equal), Ed25519 ix construction (bounds/offsets parsed by program unit test), error mapping table.
- Unit (Program): existing tests for sizes; add tests for each error path with crafted ix: BadEd25519Order, DomainSeparation mismatch, NonMonotonicSeq, RangeOverlap, ClockSkew, AggregatorMismatch.
- Unit (Indexer): decode ProofRecord/ValidatorRecord with golden account bytes; DB upsert idempotency.
- Integration:
  - Devnet: deploy program, initialize config, register validator, run orchestrator and indexer; anchor one proof; assert DB row matches on-chain, `commitment_level >= 1` after reconciliation.
- E2E Negative Matrix:
  - wrong chain_id, wrong aggregator_pubkey, missing ComputeBudget, two Ed25519 ixs, DS msg_len mismatch, proof_hash tamper, slot gap, seq non-monotonic.

---

## 24) Observability

- Logs: JSON lines
  - `orchestrator.prove.start|end` with durations (ms), artifact_id
  - `orchestrator.anchor.submit` with txid, ds_hash, seq
  - `indexer.commitment.update` with txid, level
- Health:
  - `GET /health` → `{ status: "ok", version }`
- Metrics (optional): Prometheus counters for `prove_success_total`, `anchor_success_total`, `indexer_commitment_updates_total`.

---

## 25) Security & Key Management

- Aggregator secret file permission `0600`; never commit to VCS.
- Validate `secretKey` length = 64 hex bytes; reject otherwise.
- Rate-limit `POST /anchor` by IP and Idempotency-Key.
- Validate all hex inputs; enforce lengths; lower-case normalization.
- `.env` pinned and example file provided; secrets loaded only at boot.

---

## 26) Rollout & Demo Script (Step-by-Step)

1) Provision devnet accounts and SPL mint; record public keys.
2) Deploy `validator_lock`; run `initialize` with chain_id=103.
3) Register one validator with exactly 1 zKSL locked.
4) Start orchestrator and indexer.
5) Create artifact via `POST /artifact` (or `POST /prove`).
6) Anchor via `POST /anchor`; capture txid.
7) Verify on-chain via `solana confirm <txid>` and `solana account <proof_record_pda>`.
8) Verify DB row exists and commitment updated to `>=1`.
9) Rotate aggregator key via `update_config` and anchor another proof with `seq+1`.

---

## 27) Future Work (Beyond POC)

- Full zk-BPF AIR; instruction tables; memory permutation arguments; batch Ed25519 MSM.
- Prover marketplace (PBS-like); auctions; revenue splitting.
- Data Availability Sampling integration; populate `da_params`.
- Slashing conditions for missed proofs; governance for `paused` and admin rotation.

---

This plan is deterministic, byte-precise, and fully aligned with the Whitepaper and current code. It is realistic to build: all primitives exist today (Anchor, web3.js, Blake3, Ed25519, Winterfell), and the on-chain constraints are already implemented. Executing the milestones yields a demonstrable devnet POC with verifiable cryptographic artifacts and on-chain anchoring, ready for stakeholder demos and iterative hardening.

---

## 28) Deterministic Engineering Manifesto (No Assumptions)

- Time & Clock
  - All signatures include `timestamp` bounded by clock skew; for tests, freeze time to `SOURCE_DATE_EPOCH` or inject a fixed timestamp.
  - CI sets `TZ=UTC`, `LC_ALL=C`, and uses `date -u` for any scripted timestamps.
- Locale & Encoding
  - All text I/O is UTF-8 without BOM. JSON is UTF-8, LF newlines only.
  - Hex strings normalized to lowercase before persistence.
- File Paths & Newlines
  - All generated files use LF. Paths in artifacts use forward slashes; runtime uses `path.posix` in Node.
- Sorting & Map Iteration
  - Never rely on implicit object key order. Canonicalization sorts keys lexicographically for all nested objects.
- Randomness
  - No PRNG in critical paths. Where seeds are needed for tests or fuzzing, they are fixed and recorded.
- External Dependencies
  - Every external call has a deterministic fallback: for devnet E2E we accept nondeterministic txids and blockhashes but record them; for pure reproducibility we run local validator-led tests.
- Concurrency
  - Orchestrator POST handlers are idempotent (Idempotency-Key). Internal operations serialize on `artifact_id` to avoid race conditions when writing files.
- Numeric Types
  - All on-chain integers explicitly LE. Off-chain JSON uses numbers for small u64 that fit JS, and strings for larger values. Internal validation ensures no precision loss.
- Color/TTY
  - CLI and logs disable color in CI (`NO_COLOR=1`, `FORCE_COLOR` unset) to produce deterministic output.

---

## 29) Known-Answer Tests (KATs) — Golden Vectors

KAT corpus lives under `scripts/kats/` and is used by both Rust and Node test suites.

- Canonicalization KATs
  - Input JSON variants (key order, whitespace, upper/lower hex) → canonical string and `proof_hash` (64 hex).
  - Golden files: `canonical_*.json`, `canonical_*.txt` (serialized bytes as hex), `proof_hash_*.txt`.
- DS Builder KATs
  - Inputs: chain_id, program_id, proof_hash, start_slot, end_slot, seq
  - Outputs: DS bytes (110) as hex, `ds_hash` (32 bytes hex).
- Ed25519 Instruction KATs
  - Constructed instruction data (single signature) and expected offsets; program unit test parses and validates.
- Borsh Payload KATs
  - Given inputs produce exact anchor data bytes (discriminator + fields) as hex; decoded back to same structure.
- PDA KATs
  - For fixed inputs, expected PDAs (base58). Cross-check with both Node and Rust.

Execution:
- Rust: `cargo test --features kats` loads golden files and asserts byte-equality.
- Node: `pnpm test:kats` compares outputs to golden fixtures.

---

## 30) Property-Based Tests (PBT)

- Canonicalization Idempotence: `canon(canon(x)) == canon(x)`.
- Canonicalization Stability: different key orders / whitespace in input yield identical `proof_hash`.
- DS Stability: recomputing DS for same inputs yields byte-identical DS and `ds_hash`.
- PDA Round Trip: PDA bytes decode back to same seeds when re-derived.
- Range/Seq Properties: generated random monotone sequences satisfy program invariants; non-monotone fail with exact errors.

Frameworks:
- Rust: `proptest` with deterministic seeds in CI (`PROPTEST_CASES=256`, fixed `PROPTEST_SEED`).
- Node: `fast-check` for JS-side helpers.

---

## 31) Fuzzing Plan

- Rust fuzz targets via `cargo-fuzz` (libFuzzer):
  - `fuzz_canonicalize`: random JSON → canonicalizer; ensure no panics; compare against JS canonicalizer for differential testing (where possible).
  - `fuzz_anchor_ix_parser`: feed random Ed25519 + Anchor payloads into a parser (mirror of on-chain checks) to ensure robust validation and no UB.
  - `fuzz_borsh_decode`: random bytes → Borsh decoder (reject invalid with no panics).
- Node fuzz (optional):
  - API fuzz for `/artifact` and `/anchor` with schemas to validate 4xx classification.

Reproducibility:
- Fuzz seeds recorded on crash; CI nightly runs limited time budgets; artifacts stored under `artifacts/fuzz/`.

---

## 32) Golden Conformance & Cross-Language Checks

- Cross-impl: Rust and Node must produce identical outputs for:
  - Canonical JSON
  - `proof_hash`
  - DS bytes and `ds_hash`
  - Borsh encoding (serialize in Rust, decode in Node, and vice-versa)
- Conformance runner:
  - `scripts/conformance.ts` iterates KAT corpus and asserts exact equality across languages; run in CI.

---

## 33) Benchmarks (Deterministic Micro & E2E)

- Micro (Rust): criterion.rs with `--sample-size` fixed and warmup count fixed.
  - Canonicalize 1KB/10KB artifacts
  - DS builder throughput
  - Ed25519 sign/verify cycles/s
- Micro (Node): benchmark harness with fixed iterations and GC runs between samples.
- E2E:
  - Orchestrator `/anchor` end-to-end latency excluding network (mock signer + local test validator).
  - Program compute unit usage ceiling captured from `simulateTransaction`; assert ≤ target budget.

All benches record machine metadata; CI only runs micro-bench smoke with strict upper bounds.

---

## 34) Lint, Style, and Policy (World-Class Baselines)

Rust (all crates):
- In `lib.rs`/`main.rs`:
  - `#![forbid(unsafe_code)]`
  - `#![deny(warnings, clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]`
  - `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::todo, clippy::unimplemented)]`
  - `#![deny(missing_docs, rustdoc::broken_intra_doc_links)]`
- `cargo fmt -- --config newline_style=Unix` in CI.
- `cargo deny check` for licenses & bans.
- `cargo audit` for vulnerabilities.

TypeScript/Node:
- `eslint` with `@typescript-eslint/recommended`, `plugin:security/recommended`, `no-implicit-any`, `no-floating-promises`.
- `prettier` with LF newlines, 2 spaces, no semicolons preference consistent across repo (choose one and lock).
- `tsconfig` strict: `strict: true`, `noImplicitAny: true`, `exactOptionalPropertyTypes: true`, `noUncheckedIndexedAccess: true`.
- Disallow `process.exit()` in libraries; use thrown errors.

Git & Hooks:
- Pre-commit: format, lint, KATs, unit tests (fast subset).
- Pre-push: full test suite excluding fuzz.

---

## 35) Reproducible Builds & Pinning

- Rust:
  - `Cargo.lock` committed.
  - Set `RUSTFLAGS` for reproducible builds where supported: `-Ccodegen-units=1 -Cembed-bitcode=no`.
  - Optionally set `SOURCE_DATE_EPOCH` in CI to freeze timestamps for artifacts.
- Node:
  - Use `pnpm install --frozen-lockfile`.
  - `package-lock.json` or `pnpm-lock.yaml` committed (choose one package manager and standardize repo-wide).
- Docker (optional):
  - Multi-stage builds pinning base images by digest, not tag.

---

## 36) CI/CD Pipeline (Deterministic Stages)

- Stage 1: Lint & Format (Rust + TS)
- Stage 2: KATs & Unit Tests (Rust + TS)
- Stage 3: Conformance Runner (Rust↔TS)
- Stage 4: Property Tests (bounded cases)
- Stage 5: Integration (local test validator) — deploy program, run orchestrator + indexer, anchor 1 proof
- Stage 6: Bench Smoke — assert latency and CU ceilings
- Nightly: Fuzz (libFuzzer) with time budget; cargo-audit; cargo-deny
- Artifacts: store golden outputs, coverage reports, and fuzz crashes.

---

## 37) Record & Replay Harness

- Record mode (devnet): capture inputs (artifact JSON, DS bytes, Ed25519 signature, Borsh payload, PDAs, recent blockhash, txid) into a `replay.json` bundle.
- Replay mode (local test validator): rebuild the exact transaction bytes and submit to a locally deterministic validator; assert program errors/success match.
- Benefits: deterministic reproduction of devnet issues without relying on the live network.

---

## 38) Deliverables Checklist

- [ ] Devnet program deployed; `declare_id!` updated and documented.
- [ ] Orchestrator `/prove` + `/anchor` with verification hook and logs.
- [ ] Prover (Winterfell) Phase A minimal AIR; CLI to generate & verify proofs.
- [ ] Indexer mirrors `ProofRecord` & `ValidatorRecord` to DB.
- [ ] KAT corpus and conformance runner (Rust↔TS) green.
- [ ] Full test matrix: Unit, PBT, Fuzz (nightly), Benches (smoke), Integration, E2E.
- [ ] CI gate with lints, denies, audits.
- [ ] Deterministic scripts in `scripts/` to bootstrap, init, and anchor.

---

This revision removes ambiguity by specifying determinism end-to-end (bytes, clocks, encodings, paths), exhaustive test modalities (KAT/PBT/Fuzz/Golden/Benches), and strict lint/static policies. It is ambitious but realistic: every item maps to available tooling and the current codebase. With these gates, fellow engineers have no room for assumptions—only mechanically verifiable contracts.
