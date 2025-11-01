import { describe, it, expect } from "vitest";
import { buildDS, canonicalize } from "../src/crypto.js";

describe("canonicalization and DS invariants (additional)", () => {
  it("canonicalize sorts nested keys and omits undefined deeply", () => {
    const a = canonicalize({
      z: 1,
      nested: { b: 2, a: 1, u: undefined },
      arr: [ { y: 2, x: 1, u: undefined }, 3 ],
      u: undefined,
    });
    const b = canonicalize({
      arr: [ { x: 1, y: 2 }, 3 ],
      nested: { a: 1, b: 2 },
      z: 1,
    });
    expect(a).toBe(b);
    expect(b).toBe("{\"arr\":[{\"x\":1,\"y\":2},3],\"nested\":{\"a\":1,\"b\":2},\"z\":1}");
  });

  it("DS has correct prefix, little-endian chain_id, and 110-byte length", () => {
    const zero32 = new Uint8Array(32);
    const chainId = 0x0102030405060708n; // specific pattern for LE check
    const { ds, dsHash } = buildDS({
      chainId,
      programId: zero32,
      proofHash: zero32,
      startSlot: 1n,
      endSlot: 2n,
      seq: 3n,
    });
    expect(ds.byteLength).toBe(110);
    // prefix bytes
    const prefix = Buffer.from(ds.subarray(0, 14)).toString("utf8");
    expect(prefix).toBe("zKSL/anchor/v1");
    // little-endian chain id at offset 14..22
    const cid = Buffer.from(ds.subarray(14, 22));
    expect(cid.equals(Buffer.from([
      0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
    ]))).toBe(true);
    // ds_hash present and 32 bytes
    expect(dsHash.byteLength).toBe(32);
  });

  it("ds_hash changes when any input changes (seq)", () => {
    const zero32 = new Uint8Array(32);
    const a = buildDS({ chainId: 1n, programId: zero32, proofHash: zero32, startSlot: 1n, endSlot: 1n, seq: 1n });
    const b = buildDS({ chainId: 1n, programId: zero32, proofHash: zero32, startSlot: 1n, endSlot: 1n, seq: 2n });
    expect(Buffer.from(a.dsHash).equals(Buffer.from(b.dsHash))).toBe(false);
  });
});


