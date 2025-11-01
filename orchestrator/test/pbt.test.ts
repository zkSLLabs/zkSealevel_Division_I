import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { canonicalize, buildDS } from "../src/crypto.js";

describe("property-based tests", () => {
  it("canonicalization is idempotent and stable", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.jsonValue({ maxDepth: 3 }),
        async (v) => {
          // Only test JSON-serializable subsets; undefined is filtered by canonicalizer
          const s1 = canonicalize(v as unknown);
          const parsed = JSON.parse(s1);
          const s2 = canonicalize(parsed);
          expect(s2).toBe(s1);
        },
      ),
      { numRuns: 64 },
    );
  });

  it("DS stability for same inputs produces identical bytes", async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.bigUintN(64),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.uint8Array({ minLength: 32, maxLength: 32 }),
        fc.bigUintN(64),
        fc.bigUintN(64),
        fc.bigUintN(64),
        async (chainId, programId, proofHash, start, end, seq) => {
          const a = buildDS({
            chainId,
            programId,
            proofHash,
            startSlot: start,
            endSlot: end,
            seq,
          });
          const b = buildDS({
            chainId,
            programId,
            proofHash,
            startSlot: start,
            endSlot: end,
            seq,
          });
          expect(Buffer.from(a.ds).equals(Buffer.from(b.ds))).toBe(true);
          expect(Buffer.from(a.dsHash).equals(Buffer.from(b.dsHash))).toBe(true);
        },
      ),
      { numRuns: 64 },
    );
  });
});


