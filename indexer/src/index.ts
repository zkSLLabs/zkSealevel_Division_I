import dotenv from "dotenv";
dotenv.config({ path: process.cwd() + "/.env" });

import { Client as PgClient } from "pg";
import * as web3 from "@solana/web3.js";
import * as bs58 from "bs58";

interface DecodedProofRecord {
  artifact_id: string;
  start_slot: bigint;
  end_slot: bigint;
  proof_hash: Buffer;
  artifact_len: number;
  state_root_before: Buffer;
  state_root_after: Buffer;
  submitted_by: string;
  aggregator_pubkey: string;
  timestamp: bigint;
  seq: bigint;
  ds_hash: Buffer;
}

interface DecodedValidatorRecord {
  pubkey: string;
  escrow: string;
  lock_ts: number;
  status: "Active" | "Unlocked";
  num_accepts: string;
}

async function main(): Promise<void> {
  const databaseUrl = process.env.DATABASE_URL || "postgres://postgres:postgres@localhost:5432/zksl";
  const rpcUrl = process.env.RPC_URL || "http://localhost:8899";
  const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
  if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");

  const pg = new PgClient({ connectionString: databaseUrl });
  await pg.connect();

  const programId = new web3.PublicKey(programIdStr);
  const connection = new web3.Connection(rpcUrl, { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });

  const prDisc = sha256_8("account:ProofRecord");
  const vrDisc = sha256_8("account:ValidatorRecord");

  // eslint-disable-next-line no-console
  console.log("indexer started");
  try {
    await subscribeProgramAccounts({ connection, programId, prDisc, vrDisc, pg });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.warn("ws subscribe failed, will continue with polling:", e);
  }
  // eslint-disable-next-line no-constant-condition
  while (true) {
    await scanOnce({ connection, programId, prDisc, vrDisc, pg });
    await reconcilePending({ connection, pg });
    await sleep(20000);
  }
}

async function scanOnce(params: { connection: web3.Connection; programId: web3.PublicKey; prDisc: Buffer; vrDisc: Buffer; pg: PgClient }): Promise<void> {
  const { connection, programId, prDisc, vrDisc, pg } = params;
  await pg.query(`UPDATE indexer_state SET last_scan_ts = NOW() WHERE id = 1`);
  const accounts = await connection.getProgramAccounts(programId);
  const cur = await pg.query(`SELECT last_seen_slot FROM indexer_state WHERE id = 1`);
  const lastSeen: bigint = cur.rows?.[0]?.last_seen_slot ? BigInt(cur.rows[0].last_seen_slot) : 0n;
  let maxSlot: bigint = lastSeen;
  for (const acc of accounts) {
    const data: Buffer = acc.account.data as Buffer;
    const head = data.subarray(0, 8);
    if (head.equals(prDisc)) {
      const pr = decodeProofRecord(data);
      if (pr.end_slot <= lastSeen) continue;
      const txid = await firstSignatureForAddress(connection, acc.pubkey);
      const commitment = await commitmentOfSig(connection, txid);
      await upsertProof(pg, { ...pr, txid, commitment_level: commitment });
      if (commitment >= 1 && txid) {
        await updateLastSignature(pg, txid);
      }
      if (pr.end_slot > maxSlot) maxSlot = pr.end_slot;
    } else if (head.equals(vrDisc)) {
      const vr = decodeValidatorRecord(data);
      await upsertValidator(pg, vr);
    }
  }
  try {
    const slot = await connection.getSlot();
    await pg.query(`UPDATE indexer_state SET last_seen_slot = $1 WHERE id = 1`, [slot.toString()]);
  } catch (_) {}
  try {
    if (maxSlot > lastSeen) {
      await pg.query(`UPDATE indexer_state SET last_seen_slot = $1 WHERE id = 1`, [maxSlot.toString()]);
    }
  } catch (_) {}
}

function decodeProofRecord(data: Buffer): DecodedProofRecord {
  let o = 8; // skip discriminator
  const artifactId = data.subarray(o, o + 16); o += 16;
  const start = data.readBigUInt64LE(o); o += 8;
  const end = data.readBigUInt64LE(o); o += 8;
  const proofHash = data.subarray(o, o + 32); o += 32;
  const artLen = data.readUInt32LE(o); o += 4;
  const srb = data.subarray(o, o + 32); o += 32;
  const sra = data.subarray(o, o + 32); o += 32;
  const submittedBy = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const aggregator = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const ts = data.readBigInt64LE(o); o += 8;
  const seq = data.readBigUInt64LE(o); o += 8;
  const dsHash = data.subarray(o, o + 32); o += 32;
  return {
    artifact_id: uuidFrom16(artifactId),
    start_slot: start,
    end_slot: end,
    proof_hash: Buffer.from(proofHash),
    artifact_len: artLen,
    state_root_before: Buffer.from(srb),
    state_root_after: Buffer.from(sra),
    submitted_by: submittedBy,
    aggregator_pubkey: aggregator,
    timestamp: ts,
    seq,
    ds_hash: Buffer.from(dsHash),
  };
}

async function firstSignatureForAddress(connection: web3.Connection, address: web3.PublicKey): Promise<string> {
  const sigs = await connection.getSignaturesForAddress(address, { limit: 1 }, "confirmed");
  return sigs[0]?.signature || "";
}

async function commitmentOfSig(connection: web3.Connection, sig: string): Promise<number> {
  if (!sig) return 0;
  const st = await connection.getSignatureStatuses([sig], { searchTransactionHistory: true });
  const s = st.value[0];
  const cs = s?.confirmationStatus;
  return cs === "finalized" ? 2 : cs === "confirmed" ? 1 : 0;
}

async function upsertProof(pg: PgClient, p: DecodedProofRecord & { txid: string; commitment_level: number }): Promise<void> {
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

function sha256_8(s: string): Buffer {
  const crypto = require("node:crypto");
  const h = crypto.createHash("sha256").update(s, "utf8").digest();
  return h.subarray(0, 8);
}

function uuidFrom16(b: Buffer): string {
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function sleep(ms: number): Promise<void> { return new Promise((r) => setTimeout(r, ms)); }

async function subscribeProgramAccounts(params: { connection: web3.Connection; programId: web3.PublicKey; prDisc: Buffer; vrDisc: Buffer; pg: PgClient }): Promise<void> {
  const { connection, programId, prDisc, vrDisc, pg } = params;
  const id = await connection.onProgramAccountChange(programId, async (info) => {
    try {
      const data: Buffer = info.accountInfo.data as Buffer;
      const head = data.subarray(0, 8);
      if (head.equals(prDisc)) {
        const pr = decodeProofRecord(data);
        const txid = ""; // unknown in push; poller will backfill txid
        await upsertProof(pg, { ...pr, txid, commitment_level: 0 });
      } else if (head.equals(vrDisc)) {
        const vr = decodeValidatorRecord(data);
        await upsertValidator(pg, vr);
      }
    } catch (_) { /* swallow */ }
  });
  // eslint-disable-next-line no-console
  console.log("ws subscription id:", id);
}

async function reconcilePending(params: { connection: web3.Connection; pg: PgClient }): Promise<void> {
  const { connection, pg } = params;
  const res = await pg.query(
    `SELECT txid, extract(epoch from ts) AS ts_epoch FROM proofs WHERE commitment_level < 2 ORDER BY ts ASC LIMIT 100`,
  );
  if (!res.rows.length) return;
  const txids: string[] = res.rows.map((r: any) => r.txid);
  const st = await connection.getSignatureStatuses(txids, { searchTransactionHistory: true });
  for (let i = 0; i < txids.length; i++) {
    const sig = txids[i];
    const s = st.value[i];
    if (!s || s.err) {
      const row = res.rows[i];
      const age = Date.now() / 1000 - Number(row.ts_epoch);
      if (age > 60) {
        await pg.query(`DELETE FROM proofs WHERE txid = $1`, [sig]);
      }
    } else {
      const cs = s.confirmationStatus;
      const level = cs === "finalized" ? 2 : cs === "confirmed" ? 1 : 0;
      await pg.query(`UPDATE proofs SET commitment_level = $1 WHERE txid = $2`, [level, sig]);
      if (level >= 1) {
        await updateLastSignature(pg, sig);
      }
    }
  }
  await pg.query(`UPDATE indexer_state SET last_reconciled_ts = NOW() WHERE id = 1`);
}

async function updateLastSignature(pg: PgClient, sig: string): Promise<void> {
  await pg.query(`UPDATE indexer_state SET last_signature = $1 WHERE id = 1`, [sig]);
}

function decodeValidatorRecord(data: Buffer): DecodedValidatorRecord {
  let o = 8; // skip discriminator
  const validator = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const escrow = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const lock_ts = Number(data.readBigInt64LE(o)); o += 8;
  const status_u8 = data.readUInt8(o); o += 1;
  const status = status_u8 === 0 ? "Active" : "Unlocked";
  const num_accepts = data.readBigUInt64LE(o).toString(); o += 8;
  return { pubkey: validator, escrow, lock_ts, status, num_accepts };
}

async function upsertValidator(pg: PgClient, v: DecodedValidatorRecord): Promise<void> {
  await pg.query(
    `INSERT INTO validators(pubkey, status, escrow, lock_ts, num_accepts, last_seen)
     VALUES ($1, $2, $3, to_timestamp($4), $5, NOW())
     ON CONFLICT (pubkey) DO UPDATE SET status = EXCLUDED.status, num_accepts = EXCLUDED.num_accepts, last_seen = NOW()`,
    [v.pubkey, v.status, v.escrow, v.lock_ts, v.num_accepts],
  );
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});


