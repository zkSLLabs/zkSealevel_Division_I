import { describe, it, expect } from "vitest";
import { encodeAnchorProofArgsBorsh, sha256_8, u64le, i64le } from "../src/crypto.js";

describe("anchor borsh payload", () => {
  it("has correct discriminator and total length (220 bytes)", () => {
    const zero16 = new Uint8Array(16);
    const zero32 = Buffer.alloc(32, 0);
    const data = encodeAnchorProofArgsBorsh({
      artifactId: zero16,
      startLe: u64le(1n),
      endLe: u64le(1n),
      proofHash32: zero32,
      artifactLen: 0,
      stateRootBefore: zero32,
      stateRootAfter: zero32,
      aggregatorPubkey: zero32,
      timestampLe: i64le(1n),
      seqLe: u64le(1n),
      dsHash32: zero32,
    });
    expect(data.byteLength).toBe(220);
    const disc = data.subarray(0, 8);
    expect(Buffer.from(disc).equals(sha256_8("global:anchor_proof"))).toBe(true);
  });
});


