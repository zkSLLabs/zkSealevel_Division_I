-- Add last processed signature to indexer_state
ALTER TABLE indexer_state
  ADD COLUMN IF NOT EXISTS last_signature TEXT;


