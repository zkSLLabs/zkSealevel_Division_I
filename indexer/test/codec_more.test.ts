import { describe, it, expect } from "vitest";
import { decodeProofRecord, decodeValidatorRecord } from "../src/codec.js";

function disc(label: string): Buffer {
  const crypto = require("node:crypto");
  return crypto.createHash("sha256").update(label, "utf8").digest().subarray(0, 8);
}

describe("codec more vectors", () => {
  it("decodes ProofRecord with zero artifact_len", () => {
    const b = Buffer.alloc(8 + 212);
    let o = 0;
    disc("account:ProofRecord").copy(b, o); o += 8;
    Buffer.alloc(16, 0).copy(b, o); o += 16;
    b.writeBigUInt64LE(1n, o); o += 8;
    b.writeBigUInt64LE(1n, o); o += 8;
    Buffer.alloc(32, 9).copy(b, o); o += 32;
    b.writeUInt32LE(0, o); o += 4;
    Buffer.alloc(32, 2).copy(b, o); o += 32;
    Buffer.alloc(32, 3).copy(b, o); o += 32;
    Buffer.alloc(32, 4).copy(b, o); o += 32;
    Buffer.alloc(32, 5).copy(b, o); o += 32;
    b.writeBigInt64LE(0n, o); o += 8;
    b.writeBigUInt64LE(1n, o); o += 8;
    Buffer.alloc(32, 6).copy(b, o); o += 32;
    const pr = decodeProofRecord(b);
    expect(pr.artifact_len).toBe(0);
    expect(pr.start_slot).toBe(1n);
    expect(pr.end_slot).toBe(1n);
  });

  it("decodes ProofRecord with max artifact_len", () => {
    const b = Buffer.alloc(8 + 212);
    let o = 0;
    disc("account:ProofRecord").copy(b, o); o += 8;
    Buffer.alloc(16, 0).copy(b, o); o += 16;
    b.writeBigUInt64LE(10n, o); o += 8;
    b.writeBigUInt64LE(20n, o); o += 8;
    Buffer.alloc(32, 9).copy(b, o); o += 32;
    b.writeUInt32LE(0xffffffff, o); o += 4;
    Buffer.alloc(32, 2).copy(b, o); o += 32;
    Buffer.alloc(32, 3).copy(b, o); o += 32;
    Buffer.alloc(32, 4).copy(b, o); o += 32;
    Buffer.alloc(32, 5).copy(b, o); o += 32;
    b.writeBigInt64LE(123n, o); o += 8;
    b.writeBigUInt64LE(42n, o); o += 8;
    Buffer.alloc(32, 6).copy(b, o); o += 32;
    const pr = decodeProofRecord(b);
    expect(pr.artifact_len).toBe(0xffffffff);
    expect(pr.seq).toBe(42n);
  });

  it("decodes ValidatorRecord status Unlocked", () => {
    const b = Buffer.alloc(8 + 32 + 32 + 8 + 1 + 8 + 47);
    let o = 0;
    disc("account:ValidatorRecord").copy(b, o); o += 8;
    Buffer.alloc(32, 7).copy(b, o); o += 32;
    Buffer.alloc(32, 8).copy(b, o); o += 32;
    b.writeBigInt64LE(20n, o); o += 8;
    b.writeUInt8(1, o); o += 1; // Unlocked
    b.writeBigUInt64LE(0n, o); o += 8;
    const vr = decodeValidatorRecord(b);
    expect(vr.status).toBe("Unlocked");
  });

  it("decodes ValidatorRecord status Active", () => {
    const b = Buffer.alloc(8 + 32 + 32 + 8 + 1 + 8 + 47);
    let o = 0;
    disc("account:ValidatorRecord").copy(b, o); o += 8;
    Buffer.alloc(32, 7).copy(b, o); o += 32;
    Buffer.alloc(32, 8).copy(b, o); o += 32;
    b.writeBigInt64LE(0n, o); o += 8;
    b.writeUInt8(0, o); o += 1; // Active
    b.writeBigUInt64LE(123n, o); o += 8;
    const vr = decodeValidatorRecord(b);
    expect(vr.status).toBe("Active");
    expect(vr.num_accepts).toBe("123");
  });

  it("decodes ProofRecord ds_hash copied", () => {
    const b = Buffer.alloc(8 + 212 + 32);
    let o = 0;
    disc("account:ProofRecord").copy(b, o); o += 8;
    Buffer.alloc(16, 0).copy(b, o); o += 16;
    b.writeBigUInt64LE(1n, o); o += 8;
    b.writeBigUInt64LE(2n, o); o += 8;
    Buffer.alloc(32, 1).copy(b, o); o += 32;
    b.writeUInt32LE(10, o); o += 4;
    Buffer.alloc(32, 2).copy(b, o); o += 32;
    Buffer.alloc(32, 3).copy(b, o); o += 32;
    Buffer.alloc(32, 4).copy(b, o); o += 32;
    Buffer.alloc(32, 5).copy(b, o); o += 32;
    b.writeBigInt64LE(10n, o); o += 8;
    b.writeBigUInt64LE(11n, o); o += 8;
    const marker = Buffer.alloc(32, 0xab); marker.copy(b, o); o += 32;
    const pr = decodeProofRecord(b);
    expect(pr.ds_hash.equals(Buffer.alloc(32, 0xab))).toBe(true);
  });

  it("decodes ValidatorRecord lock_ts number", () => {
    const b = Buffer.alloc(8 + 32 + 32 + 8 + 1 + 8 + 47);
    let o = 0;
    disc("account:ValidatorRecord").copy(b, o); o += 8;
    Buffer.alloc(32, 7).copy(b, o); o += 32;
    Buffer.alloc(32, 8).copy(b, o); o += 32;
    b.writeBigInt64LE(99n, o); o += 8;
    b.writeUInt8(0, o); o += 1;
    b.writeBigUInt64LE(0n, o); o += 8;
    const vr = decodeValidatorRecord(b);
    expect(vr.lock_ts).toBe(99);
  });
});


