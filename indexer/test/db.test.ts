import { describe, it, expect } from "vitest";
import { upsertProof } from "../src/db.js";

const mockPg = () => {
  const calls: any[] = [];
  return {
    pg: { query: async (...args: any[]) => { calls.push(args); } },
    calls,
  } as const;
};

describe("db upserts", () => {
  it("upsertProof uses ON CONFLICT to update commitment_level", async () => {
    const { pg, calls } = mockPg();
    await upsertProof(pg as any, {
      artifact_id: "00000000-0000-0000-0000-000000000001",
      start_slot: 1n,
      end_slot: 2n,
      proof_hash: Buffer.alloc(32, 1),
      ds_hash: Buffer.alloc(32, 2),
      artifact_len: 0,
      state_root_before: Buffer.alloc(32, 3),
      state_root_after: Buffer.alloc(32, 4),
      submitted_by: "Sb",
      aggregator_pubkey: "Ag",
      timestamp: 10n,
      seq: 1n,
      txid: "tx",
      commitment_level: 1,
    });
    expect(calls.length).toBe(1);
    const sql = String(calls[0][0]);
    expect(sql.includes("ON CONFLICT (proof_hash, seq) DO UPDATE SET commitment_level")).toBe(true);
  });
});


