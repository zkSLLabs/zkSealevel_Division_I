-- Initial schema for zkSealevel per Complete_Architecture.md
CREATE TABLE IF NOT EXISTS validators (
  pubkey TEXT PRIMARY KEY,
  status TEXT NOT NULL CHECK (status IN ('Active','Unlocked')),
  escrow TEXT NOT NULL,
  lock_ts TIMESTAMPTZ NOT NULL,
  unlock_ts TIMESTAMPTZ,
  num_accepts BIGINT NOT NULL DEFAULT 0,
  last_seen TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS proofs (
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

CREATE TABLE IF NOT EXISTS metrics (
  name TEXT,
  ts TIMESTAMPTZ,
  value DOUBLE PRECISION
);

CREATE INDEX IF NOT EXISTS proofs_hash_idx ON proofs (proof_hash);
CREATE INDEX IF NOT EXISTS proofs_ts_idx ON proofs (ts);
CREATE INDEX IF NOT EXISTS proofs_ds_idx ON proofs (ds_hash);
CREATE INDEX IF NOT EXISTS proofs_range_idx ON proofs (start_slot, end_slot);
CREATE INDEX IF NOT EXISTS validators_status_idx ON validators (status);
CREATE INDEX IF NOT EXISTS validators_last_seen_idx ON validators (last_seen);


