import { describe, it, expect } from "vitest";
import { decodeProofRecord, decodeValidatorRecord } from "../src/codec.js";

function disc(label: string): Buffer {
  const crypto = require("node:crypto");
  return crypto.createHash("sha256").update(label, "utf8").digest().subarray(0, 8);
}

describe("indexer codec", () => {
  it("decodes ProofRecord from raw buffer", () => {
    const b = Buffer.alloc(8 + 212);
    let o = 0;
    disc("account:ProofRecord").copy(b, o); o += 8;
    // artifact_id [16]
    Buffer.from("00000000000000000000000000000001", "hex").copy(b, o); o += 16;
    // start_slot u64 LE (2), end_slot u64 LE (3)
    b.writeBigUInt64LE(2n, o); o += 8;
    b.writeBigUInt64LE(3n, o); o += 8;
    // proof_hash [32]
    Buffer.alloc(32, 1).copy(b, o); o += 32;
    // artifact_len u32
    b.writeUInt32LE(123, o); o += 4;
    // state roots [32] x2
    Buffer.alloc(32, 2).copy(b, o); o += 32;
    Buffer.alloc(32, 3).copy(b, o); o += 32;
    // submitted_by [32]
    Buffer.alloc(32, 4).copy(b, o); o += 32;
    // aggregator_pubkey [32]
    Buffer.alloc(32, 5).copy(b, o); o += 32;
    // timestamp i64
    b.writeBigInt64LE(10n, o); o += 8;
    // seq u64
    b.writeBigUInt64LE(11n, o); o += 8;
    // ds_hash [32]
    Buffer.alloc(32, 6).copy(b, o); o += 32;

    const pr = decodeProofRecord(b);
    expect(pr.artifact_id).toBe("00000000-0000-0000-0000-000000000001");
    expect(pr.start_slot).toBe(2n);
    expect(pr.end_slot).toBe(3n);
    expect(pr.artifact_len).toBe(123);
    expect(pr.seq).toBe(11n);
  });

  it("decodes ValidatorRecord from raw buffer", () => {
    const b = Buffer.alloc(8 + 32 + 32 + 8 + 1 + 8 + 47);
    let o = 0;
    disc("account:ValidatorRecord").copy(b, o); o += 8;
    Buffer.alloc(32, 7).copy(b, o); o += 32; // validator
    Buffer.alloc(32, 8).copy(b, o); o += 32; // escrow
    b.writeBigInt64LE(20n, o); o += 8; // lock_ts
    b.writeUInt8(0, o); o += 1; // Active
    b.writeBigUInt64LE(5n, o); o += 8; // num_accepts
    // reserved [47] left zero
    const vr = decodeValidatorRecord(b);
    expect(vr.lock_ts).toBe(20);
    expect(vr.status).toBe("Active");
    expect(vr.num_accepts).toBe("5");
  });
});


