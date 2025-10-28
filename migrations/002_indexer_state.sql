-- Indexer durable state
CREATE TABLE IF NOT EXISTS indexer_state (
  id SMALLINT PRIMARY KEY DEFAULT 1,
  last_scan_ts TIMESTAMPTZ
);

INSERT INTO indexer_state (id, last_scan_ts)
VALUES (1, NOW())
ON CONFLICT (id) DO NOTHING;


