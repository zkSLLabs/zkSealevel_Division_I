zkSealevel (zKSL) — Build Runbook

Quickstart (localnet/devnet-ready):

1) Start core services

   docker compose -f docker/compose.yml up -d

2) Bootstrap (build, deploy program, seed env)

   ./scripts/dev_bootstrap.sh

3) Demo flow (devnet)

   cli: zksl register --keypair ./keys/validator.json --mint 9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump --cluster devnet
   cli: zksl prove --input sample_state.json --out ./data/artifacts/A.json
   cli: zksl anchor --artifact ./data/artifacts/A.json --keypair ./keys/aggregator.json
   cli: zksl status --validator <PUBKEY>
   cli: zksl unlock --keypair ./keys/validator.json

See 1_Master_Blueprint.md and 2_Complete_Architecture.md for the authoritative specification.
Note: `$zKSL` is an already-launched pump.fun SPL mint; set `ZKSL_MINT=9Yn6bnF3eKLqocUVMxduh7WWqgQZ8DvWQDYTX9Ncpump` in your environment.

Environment:
- Orchestrator reads: `RPC_URL`, `WS_URL`, `PROGRAM_ID_VALIDATOR_LOCK`, `ZKSL_MINT`, `CHAIN_ID`, `PORT`, `AGGREGATOR_KEYPAIR_PATH`.
- CLI uses `ORCH_URL` to reach orchestrator (default `http://localhost:8080`).

Containers:
- `docker/compose.yml` builds `orchestrator`, `prover`, and `indexer` images. Ensure `.env` contains required keys or pass via compose env.


