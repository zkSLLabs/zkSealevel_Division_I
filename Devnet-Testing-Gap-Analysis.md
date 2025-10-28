## Total Devnet Test Gaps

Anchors:
- Source of truth for requirements: `Devnet-POC-Execution-Plan.md` (Sections 23, 29–33, 34, 11, 19, 26).
- Current repository state as committed (no external assumptions).

### Existing test assets (from repo)
- Anchor program unit tests: size checks and DS length only.
  - `programs/validator_lock/src/lib.rs` contains two tests under `#[cfg(test)]` that assert account sizes and DS length.
- Known‑Answer Test scripts (standalone, not wired to a test runner):
  - `scripts/kats/ds_kat.js` (DS length/hash); `scripts/kats/ds_negative_kat.js` (DS changes when fields change); `scripts/kats/anchor_proof_kat.js` (anchor args length/discriminator).
- E2E helper script for localnet (manual, not CI‑wired):
  - `scripts/e2e_localnet.ts` (POST /artifact → POST /anchor → GET /proof loop).
- Static analysis flags in Rust crates (`#![forbid(unsafe_code)]`, `#![deny(..., clippy::pedantic, ...)]`), but the bootstrap script does not fail the build on clippy errors (`|| true`).

### Gaps vs POC Test Plan

1) Unit Tests — Orchestrator (POC §23: Unit/Orchestrator)
- Missing tests for:
  - Canonicalization (golden vectors; JCS‑like ordering, undefined elision).
  - DS builder byte equality (110‑byte layout and `ds_hash`).
  - Ed25519 instruction construction bounds/offsets as parsed by on‑chain checks.
  - Error mapping table (e.g., BadEd25519Order, BadDomainSeparation, NonMonotonicSeq, RangeOverlap, ClockSkew, AggregatorMismatch → correct HTTP codes).

2) Unit Tests — Program (POC §23: Unit/Program)
- Present: size tests; DS length test.
- Missing targeted negative tests for each error path with crafted instruction sequences:
  - BadEd25519Order, BadDomainSeparation, NonMonotonicSeq, RangeOverlap, ClockSkew, AggregatorMismatch, InsufficientBudget, InvalidMint.

3) Unit Tests — Indexer (POC §23: Unit/Indexer)
- Missing tests for:
  - Decoding `ProofRecord` and `ValidatorRecord` from golden account bytes (byte‑exact field offsets).
  - DB upsert idempotency and commitment reconciliation state transitions.

4) Integration Test — Devnet happy path (POC §23: Integration; §11 Acceptance; §19 Tx Construction; §26 Rollout)
- Missing automated test that:
  - Deploys `validator_lock` to Devnet and initializes `Config` with chain_id=103 and mint.
  - Runs orchestrator/indexer; `POST /artifact` → `POST /anchor` (ComputeBudget → Ed25519 → anchor_proof order); confirms tx.
  - Asserts DB row exists for `ProofRecord` with `commitment_level ≥ 1` and cursors updated.

5) E2E Negative Matrix (POC §23: E2E Negative Matrix)
- Missing automated tests for each required negative case:
  - wrong chain_id; wrong aggregator_pubkey; missing ComputeBudget; two Ed25519 ixs; DS msg_len mismatch; proof_hash tamper; slot gap; seq non‑monotonic.

6) Known‑Answer Tests corpus (POC §29 KATs)
- Present (partial, standalone): DS KATs and anchor length KAT.
- Missing KATs for:
  - Canonicalization (input variants → canonical string and proof_hash).
  - Borsh payload hex (anchor args) round‑trip.
  - PDA derivations for all seeds (config, aggregator, range, proof, validator) for fixed inputs.
- Missing runner wiring:
  - No npm/pnpm test target to execute all KATs; only `kat:ds` exists at repo root.

7) Golden Conformance (POC §32)
- Missing cross‑language runner to assert byte‑equality between Rust and TS for:
  - Canonical JSON; proof_hash; DS bytes and ds_hash; Borsh encoding/decoding.

8) Property‑Based Tests (POC §30)
- Missing entirely (no `proptest` or `fast-check` suites):
  - Canonicalization idempotence/stability; DS stability; PDA round‑trip; range/seq properties.

9) Fuzzing (POC §31)
- Missing fuzz targets and harnesses (no `cargo-fuzz`):
  - canonicalizer; Ed25519/anchor ix parser; Borsh decoder.

10) Benchmarks (POC §33)
- Missing deterministic micro benches (Rust/Node) and E2E latency/compute ceiling smoke.

11) Lint/Style Gates (POC §34)
- Partial: strict attributes present in Rust crates, but not enforced in automation; no CI stages defined in repo to gate on lints/tests/conformance.

### Summary
- Implemented: Minimal program unit tests; standalone DS/anchor KAT scripts; localnet E2E helper.
- Missing (must add to satisfy POC): all orchestrator/indexer unit tests, comprehensive program negative tests, Devnet integration and negative E2E matrix, full KAT corpus and runner, golden conformance (Rust↔TS), property‑based tests, fuzzing targets, deterministic benches, and CI gates to enforce them.


