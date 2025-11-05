import { bench, describe } from "vitest";
import { buildDS, u64le, encodeAnchorProofArgsBorsh } from "../src/crypto.js";

describe("crypto micro-benchmarks", () => {
  bench("buildDS 10k iterations", () => {
    const programId = Buffer.alloc(32, 1);
    const proofHash = Buffer.alloc(32, 2);
    for (let i = 0; i < 10000; i++) {
      buildDS({ chainId: 103n, programId, proofHash, startSlot: 1n, endSlot: 1n, seq: 1n });
    }
  });

  bench("encodeAnchorProofArgsBorsh 10k iterations", () => {
    for (let i = 0; i < 10000; i++) {
      encodeAnchorProofArgsBorsh({
        artifactId: Buffer.alloc(16, 0),
        startLe: u64le(1n),
        endLe: u64le(1n),
        proofHash32: Buffer.alloc(32, 0),
        artifactLen: 0,
        stateRootBefore: Buffer.alloc(32, 0),
        stateRootAfter: Buffer.alloc(32, 0),
        aggregatorPubkey: Buffer.alloc(32, 1),
        timestampLe: u64le(1n),
        seqLe: u64le(1n),
        dsHash32: Buffer.alloc(32, 0),
      });
    }
  });
});


