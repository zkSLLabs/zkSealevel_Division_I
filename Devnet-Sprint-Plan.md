## Devnet Sprint Plan

### Source of truth
- This sprint plan is anchored strictly to `Devnet-POC-Execution-Plan.md` (Devnet). All tasks below exist solely to reach the Acceptance Criteria and protocol contracts defined there. No scope beyond that document is included.

### Sprint goal (maps to Section 11: Acceptance Criteria)
- Initialize on Devnet with correct config; `register_validator` succeeds; escrow holds exactly one token.
- Orchestrator constructs DS=110B, signs DS, and submits `anchor_proof` with required instruction ordering; transaction confirms.
- Program accepts only when all invariants pass (seq, range, skew, aggregator key policy).
- Indexer records a `ProofRecord` with `commitment_level ≥ confirmed` and updates cursors.

### Current state (from repository)
- Program `programs/validator_lock` implements config, 1‑token lock/unlock, and `anchor_proof` with strict preflight checks and invariants.
- Orchestrator `orchestrator/src/server.ts` implements `POST /artifact`, `POST /anchor`, canonicalization, DS builder, Ed25519 signing, and tx submission; idempotency cache present.
- Indexer `indexer/src/index.ts` decodes `ProofRecord`/`ValidatorRecord`, mirrors to Postgres, reconciles commitments (WS + polling).
- DB schema and migrations present (`migrations/*.sql`).
- CLI provides `init-config`, `register`, `unlock`, `status`.
- Docker Compose for local stack available; Prometheus/Grafana included (optional per plan).

### Gaps vs POC plan (must close)
1) Deterministic artifact identity (Section 16, 17):
   - Current `/artifact` uses a random UUID, and computes `proof_hash` before adding `artifact_id`, which can change canonical bytes later.
   - Plan requires `artifact_id = uuid_v4_from_bytes(blake3(canonical_json)[0..16])` and stable canonicalization across `/artifact` → `/anchor`.

2) Monotonic global sequence (Sections 4.7, 4.8):
   - Current `/anchor` hardcodes `seq = 1n`; must read `AggregatorState.last_seq` (PDA `["zksl","aggregator"]`) and submit `seq = last_seq + 1`.

3) Indexer dependency (runtime):
   - `indexer/src/index.ts` uses `bs58` but `indexer/package.json` does not declare it.

4) Program ID alignment (Section 7):
   - `declare_id!` uses a placeholder. Devnet deployment must set the real program ID and the repo updated accordingly.

5) Artifact loading on `/anchor` (determinism policy):
   - Current code relies on an in‑memory map; should load the stored canonical artifact from `ARTIFACT_DIR` by `artifact_id` to ensure byte stability across restarts.

6) Tests and conformance (Sections 23, 29, 32):
   - KAT scripts exist, but unit tests for orchestrator error paths and a Rust↔TS conformance runner are not present.

7) Optional per plan (not required for acceptance):
   - Prometheus metrics wiring; STARK prover Phase A integration (Section 5) is optional and can be gated after acceptance.

### Work breakdown (DoD ties back to plan sections)

T1. Add missing dependency for Indexer (unblocks runtime)
- Files: `indexer/package.json`.
- Change: add `"bs58": "^5"` to dependencies and rebuild.
- DoD: `pnpm/ npm run build` succeeds for indexer without runtime import errors. (Plan Section 8)

T2. Deterministic artifact_id and stable canonicalization
- Files: `orchestrator/src/server.ts`.
- Changes:
  - Compute canonical JSON of minimal fields, derive `proof_hash = blake3(canonical_json)`, then derive `artifact_id` deterministically from the first 16 bytes of that hash with UUID v4 variant/version bits.
  - Persist canonical JSON that includes `artifact_id` (re‑canonicalize once), and use that exact content to compute the final `proof_hash` (must remain identical by design per Section 16/17).
- DoD:
  - Repeated calls with the same inputs produce identical `artifact_id` and `proof_hash`.
  - Stored file content round‑trips unchanged for `/anchor`. (Plan Sections 4.1, 16, 17)

T3. Load artifact from disk on `/anchor`
- Files: `orchestrator/src/server.ts`.
- Changes: if not in memory, resolve `artifact_id` to path `ARTIFACT_DIR/YYYY/MM/DD/{artifact_id}.json`, read bytes, and re‑hash for `proof_hash`.
- DoD: `/anchor` works after orchestrator restart; `proof_hash` equals the one returned by `/artifact`. (Determinism policy)

T4. Implement monotonic `seq`
- Files: `orchestrator/src/server.ts`.
- Changes:
  - Derive `aggregator_state` PDA `["zksl","aggregator"]`, fetch account, parse `last_seq: u64 LE` after discriminator and aggregator pubkey.
  - Set `seq = last_seq + 1`; maintain existing key‑rotation policy via `activation_seq`.
- DoD: Program accepts non‑first anchors; repeated anchors increment `seq` by 1 and pass `NonMonotonicSeq` checks. (Plan Sections 4.7, 4.8)

T5. Devnet deploy and program ID alignment
- Files: `programs/validator_lock/src/lib.rs`, `Anchor.toml`.
- Steps:
  - Deploy to Devnet; update `declare_id!` to the deployed program ID.
  - Ensure `.env` uses `PROGRAM_ID_VALIDATOR_LOCK=<DEVNET_PROGRAM_ID>`, `RPC_URL=https://api.devnet.solana.com`, `CHAIN_ID=103`.
- DoD: `anchor keys list` shows the deployed ID; program invocations use this ID end‑to‑end. (Plan Section 7)

T6. Database migrations and indexer boot
- Files: `migrations/*.sql`, `scripts/db_migrate.sh`.
- Steps: apply migrations to the target Postgres; start indexer with `PROGRAM_ID_VALIDATOR_LOCK` and `DATABASE_URL` set.
- DoD: `validators`, `proofs`, `indexer_state` exist; indexer updates `commitment_level` and `last_signature`. (Plan Sections 8, 9)

T7. Minimal tests and KAT wiring
- Files: orchestrator test harness (add), scripts/kats.
- Steps:
  - Unit tests for canonicalization and DS builder (byte‑equality with KATs).
  - Negative tests for orchestrator error mapping (e.g., `ChainIdMismatch`).
- DoD: Tests green locally; KATs executed from a script/CI target. (Plan Sections 23, 29)

T8. Devnet runbook execution (single proof)
- Steps (Plan Sections 10, 19, 26):
  - Initialize `Config` via CLI `init-config` with Devnet `zKSL` mint and aggregator key; set `activation_seq=1`, `chain_id=103`.
  - Fund validator and mint exactly 1 token to validator ATA; run `register_validator`.
  - `POST /artifact` with minimal fields → receive `artifact_id`, `proof_hash`.
  - `POST /anchor` → tx confirms; capture `txid`.
  - Indexer reflects `ProofRecord` row with `commitment_level ≥ 1` and updates cursors.
- DoD: All acceptance bullets at the top of this plan satisfied.

### Execution order (strict)
1) T1 Indexer dependency
2) T2 Deterministic artifact_id
3) T3 `/anchor` loads from disk
4) T4 Monotonic `seq`
5) T5 Devnet deploy + program ID alignment
6) T6 DB migrate + Indexer boot
7) T7 Tests/KAT wiring
8) T8 Devnet end‑to‑end proof anchor

### Out‑of‑scope (optional per plan, can follow after acceptance)
- Metrics (Prometheus counters), Grafana dashboards.
- Prover Phase A (Winterfell) with off‑chain verification gate.

### Notes
- All byte layouts, PDA seeds, and invariants must remain exactly as specified in `Devnet-POC-Execution-Plan.md`. Any change that alters those bytes or ordering is not allowed in this sprint.


