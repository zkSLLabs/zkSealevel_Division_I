import { Client as PgClient } from "pg";
import type { DecodedProofRecord, DecodedValidatorRecord } from "./codec.js";

export async function upsertProof(pg: PgClient | { query: PgClient["query"] }, p: DecodedProofRecord & { txid: string; commitment_level: number }): Promise<void> {
  await pg.query(
    `INSERT INTO proofs (
      artifact_id, start_slot, end_slot, proof_hash, ds_hash, artifact_len, state_root_before, state_root_after,
      submitted_by, aggregator_pubkey, ts, seq, commitment_level, txid
     ) VALUES (
      $1, $2, $3, $4, $5, $6, $7, $8,
      $9, $10, to_timestamp($11), $12, $13, $14
     ) ON CONFLICT (proof_hash, seq) DO UPDATE SET commitment_level = EXCLUDED.commitment_level`,
    [
      p.artifact_id,
      p.start_slot.toString(),
      p.end_slot.toString(),
      p.proof_hash,
      p.ds_hash,
      p.artifact_len,
      p.state_root_before,
      p.state_root_after,
      p.submitted_by,
      p.aggregator_pubkey,
      Number(p.timestamp),
      p.seq.toString(),
      p.commitment_level,
      p.txid,
    ],
  );
}

export async function upsertValidator(pg: PgClient | { query: PgClient["query"] }, v: DecodedValidatorRecord): Promise<void> {
  await pg.query(
    `INSERT INTO validators(pubkey, status, escrow, lock_ts, num_accepts, last_seen)
     VALUES ($1, $2, $3, to_timestamp($4), $5, NOW())
     ON CONFLICT (pubkey) DO UPDATE SET status = EXCLUDED.status, num_accepts = EXCLUDED.num_accepts, last_seen = NOW()`,
    [v.pubkey, v.status, v.escrow, v.lock_ts, v.num_accepts],
  );
}

export async function updateLastSignature(pg: PgClient | { query: PgClient["query"] }, sig: string): Promise<void> {
  await pg.query(`UPDATE indexer_state SET last_signature = $1 WHERE id = 1`, [sig]);
}


