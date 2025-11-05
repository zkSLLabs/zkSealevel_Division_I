import { describe, it, expect } from "vitest";
import { buildDS, u64le, encodeAnchorProofArgsBorsh } from "../src/crypto.js";

// 40 KAT-like tests: deterministic DS and anchor_proof payload length
describe("KATs: DS and anchor_proof encoding", () => {
  const programId = Buffer.from(
    "4DDKoz69pr37yBMW9LVeuM7P2GHS9BQ9ctLHydbWeYxQ",
    "utf8",
  );
  const prog = Buffer.alloc(32, 7); // fixed 32-byte program id for KAT
  const proofHash = Buffer.alloc(32, 5);

  Array.from({ length: 40 }, (_, i) => i).forEach((i) => {
    it(`KAT #${i}: DS(110) and anchor_proof len(220)`, () => {
      const start = BigInt(1 + i);
      const end = BigInt(1 + i);
      const seq = BigInt(1 + i);
      const { ds, dsHash } = buildDS({
        chainId: BigInt(103),
        programId: prog,
        proofHash,
        startSlot: start,
        endSlot: end,
        seq,
      });
      expect(ds.length).toBe(110);
      expect(dsHash.length).toBe(32);

      const data = encodeAnchorProofArgsBorsh({
        artifactId: Buffer.alloc(16, 0),
        startLe: u64le(start),
        endLe: u64le(end),
        proofHash32: Buffer.from(proofHash),
        artifactLen: 0,
        stateRootBefore: Buffer.alloc(32, 0),
        stateRootAfter: Buffer.alloc(32, 0),
        aggregatorPubkey: Buffer.alloc(32, 1),
        timestampLe: u64le(BigInt(1)),
        seqLe: u64le(seq),
        dsHash32: Buffer.from(dsHash),
      });
      expect(data.length).toBe(220);
    });
  });
});


