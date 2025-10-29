import { describe, it, expect } from "vitest";
import { buildDS, canonicalize, normalizeHex32 } from "../src/crypto.js";

describe("crypto primitives", () => {
  it("buildDS produces 110-byte DS and correct hash length", () => {
    const zero32 = new Uint8Array(32);
    const { ds, dsHash } = buildDS({
      chainId: 1n,
      programId: zero32,
      proofHash: zero32,
      startSlot: 1n,
      endSlot: 1n,
      seq: 1n,
    });
    expect(ds.byteLength).toBe(110);
    expect(dsHash.byteLength).toBe(32);
  });

  it("canonicalize sorts keys and omits undefined", () => {
    const a = canonicalize({ b: 2, a: 1, x: undefined });
    const b = canonicalize({ a: 1, b: 2 });
    expect(a).toBe(b);
    expect(b).toBe("{\"a\":1,\"b\":2}");
  });

  it("normalizeHex32 lowercases valid hex", () => {
    const h = "A".repeat(64);
    expect(normalizeHex32(h)).toBe("a".repeat(64));
  });
});


