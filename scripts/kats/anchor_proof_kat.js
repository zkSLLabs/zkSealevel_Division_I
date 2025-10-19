// KAT: Anchor proof instruction encoding length/layout check
const crypto = require('node:crypto');

function sha256_8(s) {
  return crypto.createHash('sha256').update(s, 'utf8').digest().subarray(0, 8);
}

function enc64(n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return b; }
function enc32(n) { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; }

function encodeAnchorProofArgsFixed(vec) {
  const disc = sha256_8('global:anchor_proof');
  const payload = Buffer.concat([
    Buffer.from(vec.artifactId),
    enc64(vec.start),
    enc64(vec.end),
    Buffer.from(vec.proofHash32),
    enc32(vec.artifactLen),
    Buffer.from(vec.stateRootBefore),
    Buffer.from(vec.stateRootAfter),
    Buffer.from(vec.aggregatorPubkey32),
    enc64(vec.timestamp), // writes as u64 here for length parity, actual i64 has same size
    enc64(vec.seq),
    Buffer.from(vec.dsHash32),
  ]);
  return Buffer.concat([disc, payload]);
}

(function main() {
  const zero16 = Buffer.alloc(16, 0);
  const zero32 = Buffer.alloc(32, 0);
  const data = encodeAnchorProofArgsFixed({
    artifactId: zero16,
    start: 1n,
    end: 1n,
    proofHash32: zero32,
    artifactLen: 0,
    stateRootBefore: zero32,
    stateRootAfter: zero32,
    aggregatorPubkey32: zero32,
    timestamp: 1n,
    seq: 1n,
    dsHash32: zero32,
  });
  const expectedLen = 8 /*disc*/ + 212 /*payload*/;
  if (data.length !== expectedLen) throw new Error(`anchor_proof data length expected ${expectedLen}, got ${data.length}`);
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ anchor_proof_len: data.length, disc_hex: data.subarray(0,8).toString('hex') }));
})();


