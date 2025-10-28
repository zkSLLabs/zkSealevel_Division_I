// Use dynamic import in JS runtime to avoid TS type requirements during lint
// eslint-disable-next-line @typescript-eslint/no-var-requires
const blake3 = require("blake3");

function enc64(n: bigint): Buffer { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; }

export function buildDS(
  chainId: bigint,
  programId: Uint8Array,
  proofHash: Uint8Array,
  startSlot: bigint,
  endSlot: bigint,
  seq: bigint,
): { ds: Buffer; dsHash: Buffer } {
  const ds = Buffer.concat([
    Buffer.from("zKSL/anchor/v1", "utf8"),
    enc64(chainId),
    Buffer.from(programId),
    Buffer.from(proofHash),
    enc64(startSlot),
    enc64(endSlot),
    enc64(seq),
  ]);
  const dsHash = blake3.hash(ds);
  return { ds, dsHash: Buffer.from(dsHash) } as { ds: Buffer; dsHash: Buffer };
}


