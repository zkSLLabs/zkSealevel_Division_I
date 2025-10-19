// KAT: DS length and hash for fixed inputs per docs
const blake3 = require('blake3');

function enc64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }

function buildDS(chainId, programId32, proofHash32, startSlot, endSlot, seq) {
  const ds = Buffer.concat([
    Buffer.from('zKSL/anchor/v1', 'utf8'),
    enc64(chainId),
    Buffer.from(programId32),
    Buffer.from(proofHash32),
    enc64(startSlot),
    enc64(endSlot),
    enc64(seq),
  ]);
  const dsHash = blake3.hash(ds);
  return { ds, dsHash };
}

(function main() {
  const chainId = 1n;
  const programId32 = Buffer.alloc(32, 0);
  const proofHash32 = Buffer.alloc(32, 0);
  const { ds, dsHash } = buildDS(chainId, programId32, proofHash32, 1n, 1n, 1n);
  if (ds.length !== 110) throw new Error(`DS length expected 110, got ${ds.length}`);
  // Print the vector for external verification
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ ds_len: ds.length, ds_hash_hex: Buffer.from(dsHash).toString('hex') }));
})();


