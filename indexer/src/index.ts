import dotenv from "dotenv";
dotenv.config({ path: process.cwd() + "/.env" });

import { Client as PgClient } from "pg";
import * as web3 from "@solana/web3.js";
import * as bs58 from "bs58";
import { decodeProofRecord, decodeValidatorRecord, DecodedProofRecord, DecodedValidatorRecord } from "./codec.js";
import { upsertProof, upsertValidator, updateLastSignature } from "./db.js";

// types and decode functions moved to codec.ts for testability

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

// decodeProofRecord is imported

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


function sha256_8(s: string): Buffer {
  const crypto = require("node:crypto");
  const h = crypto.createHash("sha256").update(s, "utf8").digest();
  return h.subarray(0, 8);
}

// uuidFrom16 moved to codec.ts

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


// decodeValidatorRecord is imported

// db helpers imported

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});


