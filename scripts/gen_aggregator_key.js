#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const out = process.argv[2] || process.env.AGGREGATOR_KEYPAIR_PATH || path.join('keys','aggregator.json');
const dir = path.dirname(out);
fs.mkdirSync(dir, { recursive: true });
if (fs.existsSync(out)) {
  console.log(`[zksl] aggregator key already exists at ${out}`);
  process.exit(0);
}
const hex = crypto.randomBytes(64).toString('hex');
fs.writeFileSync(out, JSON.stringify({ secretKey: hex }, null, 2));
console.log(`[zksl] wrote aggregator key to ${out}`);


