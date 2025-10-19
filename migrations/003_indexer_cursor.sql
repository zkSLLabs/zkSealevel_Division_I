-- Extend indexer_state with durable cursor fields
ALTER TABLE indexer_state
  ADD COLUMN IF NOT EXISTS last_seen_slot BIGINT,
  ADD COLUMN IF NOT EXISTS last_reconciled_ts TIMESTAMPTZ;


