// Negative KAT: DS hash must change if any field changes
const blake3 = require('blake3');

function enc64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }

function buildDS(chainId, programId32, proofHash32, startSlot, endSlot, seq) {
  return Buffer.concat([
    Buffer.from('zKSL/anchor/v1', 'utf8'),
    enc64(chainId),
    Buffer.from(programId32),
    Buffer.from(proofHash32),
    enc64(startSlot),
    enc64(endSlot),
    enc64(seq),
  ]);
}

(function main() {
  const zero32 = Buffer.alloc(32, 0);
  const ds1 = buildDS(1n, zero32, zero32, 1n, 1n, 1n);
  const ds2 = buildDS(2n, zero32, zero32, 1n, 1n, 1n);
  const h1 = blake3.hash(ds1);
  const h2 = blake3.hash(ds2);
  if (Buffer.from(h1).equals(Buffer.from(h2))) throw new Error('DS hash must differ when chainId differs');
  // eslint-disable-next-line no-console
  console.log('ds_negative_kat: ok');
})();


