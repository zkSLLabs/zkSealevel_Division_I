import { describe, it, expect } from "vitest";
import { upsertProof, upsertValidator, updateLastSignature } from "../src/db.js";

function mockPg() {
  const calls: any[] = [];
  return {
    pg: { query: async (...args: any[]) => { calls.push(args); } },
    calls,
  } as const;
}

describe("db layer SQL generation (more)", () => {
  it("upsertValidator sets last_seen via NOW()", async () => {
    const { pg, calls } = mockPg();
    await upsertValidator(pg as any, {
      pubkey: "Pk",
      status: "Active",
      escrow: "Es",
      lock_ts: 1,
      num_accepts: "0",
    });
    const sql = String(calls[0][0]);
    expect(sql.includes("NOW()")).toBe(true);
  });

  it("upsertProof uses to_timestamp for ts", async () => {
    const { pg, calls } = mockPg();
    await upsertProof(pg as any, {
      artifact_id: "00000000-0000-0000-0000-000000000000",
      start_slot: 1n,
      end_slot: 1n,
      proof_hash: Buffer.alloc(32, 1),
      ds_hash: Buffer.alloc(32, 2),
      artifact_len: 0,
      state_root_before: Buffer.alloc(32, 3),
      state_root_after: Buffer.alloc(32, 4),
      submitted_by: "Sb",
      aggregator_pubkey: "Ag",
      timestamp: 10n,
      seq: 1n,
      commitment_level: 1,
      txid: "tx",
    });
    const sql = String(calls[0][0]);
    expect(sql.includes("to_timestamp($11)")).toBe(true);
  });

  it("upsertProof updates commitment_level on conflict", async () => {
    const { pg, calls } = mockPg();
    await upsertProof(pg as any, {
      artifact_id: "00000000-0000-0000-0000-000000000000",
      start_slot: 2n,
      end_slot: 2n,
      proof_hash: Buffer.alloc(32, 0xaa),
      ds_hash: Buffer.alloc(32, 0xbb),
      artifact_len: 1,
      state_root_before: Buffer.alloc(32, 1),
      state_root_after: Buffer.alloc(32, 2),
      submitted_by: "Sb",
      aggregator_pubkey: "Ag",
      timestamp: 0n,
      seq: 2n,
      commitment_level: 2,
      txid: "tx2",
    });
    const sql = String(calls[0][0]);
    expect(sql.includes("ON CONFLICT (proof_hash, seq) DO UPDATE SET commitment_level")).toBe(true);
  });

  it("updateLastSignature updates indexer_state row", async () => {
    const { pg, calls } = mockPg();
    await updateLastSignature(pg as any, "sig");
    const sql = String(calls[0][0]);
    expect(sql.includes("UPDATE indexer_state SET last_signature")).toBe(true);
  });

  // 4 more small parameter order assertions
  it("upsertProof param order: artifact_id first", async () => {
    const { pg, calls } = mockPg();
    await upsertProof(pg as any, {
      artifact_id: "id",
      start_slot: 3n,
      end_slot: 4n,
      proof_hash: Buffer.alloc(32, 0),
      ds_hash: Buffer.alloc(32, 0),
      artifact_len: 0,
      state_root_before: Buffer.alloc(32, 0),
      state_root_after: Buffer.alloc(32, 0),
      submitted_by: "Sb",
      aggregator_pubkey: "Ag",
      timestamp: 0n,
      seq: 0n,
      commitment_level: 0,
      txid: "tx",
    });
    const params = calls[0][1];
    expect(params[0]).toBe("id");
  });

  it("upsertProof param order: txid last", async () => {
    const { pg, calls } = mockPg();
    await upsertProof(pg as any, {
      artifact_id: "id",
      start_slot: 0n,
      end_slot: 0n,
      proof_hash: Buffer.alloc(32, 0),
      ds_hash: Buffer.alloc(32, 0),
      artifact_len: 0,
      state_root_before: Buffer.alloc(32, 0),
      state_root_after: Buffer.alloc(32, 0),
      submitted_by: "Sb",
      aggregator_pubkey: "Ag",
      timestamp: 0n,
      seq: 0n,
      commitment_level: 0,
      txid: "txX",
    });
    const params = calls[0][1];
    expect(params[params.length - 1]).toBe("txX");
  });
});


