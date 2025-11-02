// Canonicalization KAT: produce canonical JSON and proof_hash for fixed inputs
const blake3 = require('blake3');

function canonicalize(value) {
  return stringifyCanonical(value);
  function stringifyCanonical(v) {
    if (v === null) return 'null';
    const t = typeof v;
    if (t === 'number' || t === 'boolean' || t === 'string') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(stringifyCanonical).join(',') + ']';
    if (t === 'object') {
      const obj = v;
      const entries = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort()
        .map((k) => JSON.stringify(k) + ':' + stringifyCanonical(obj[k]));
      return '{' + entries.join(',') + '}';
    }
    return JSON.stringify(v);
  }
}

(function main() {
  const variants = [
    { a: 1, b: 2, x: undefined },
    { b: 2, a: 1 },
    { nested: { z: 0, a: 1 }, arr: [ { y: 2, x: 1 }, 3 ] },
  ];
  const out = [];
  for (const v of variants) {
    const canon = canonicalize(v);
    const hashHex = Buffer.from(blake3.hash(Buffer.from(canon, 'utf8'))).toString('hex');
    out.push({ input: v, canonical: canon, proof_hash: hashHex });
  }
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ vectors: out }, null, 2));
})();


