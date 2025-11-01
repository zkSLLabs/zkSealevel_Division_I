#!/usr/bin/env node
/* Conformance: Node vs Rust (prover) — proof_hash equality */
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const blake3 = require("blake3");

function canonicalize(value) {
  return stringifyCanonical(value);
  function stringifyCanonical(v) {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "number" || t === "boolean" || t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + v.map(stringifyCanonical).join(",") + "]";
    if (t === "object") {
      const obj = v;
      const entries = Object.keys(obj)
        .filter((k) => obj[k] !== undefined)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + stringifyCanonical(obj[k]));
      return "{" + entries.join(",") + "}";
    }
    return JSON.stringify(v);
  }
}

function fatal(msg) {
  // eslint-disable-next-line no-console
  console.error(`[conformance] ${msg}`);
  process.exit(1);
}

function main() {
  const agg = process.env.AGGREGATOR_KEYPAIR_PATH || "./keys/aggregator.json";
  const programId = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
  const chainId = process.env.CHAIN_ID || "1";
  if (!programId) fatal("PROGRAM_ID_VALIDATOR_LOCK is required in env");
  if (!fs.existsSync(agg)) fatal(`Aggregator key not found at ${agg}`);

  const artifact = {
    artifact_id: "00000000-0000-4000-8000-000000000001",
    start_slot: 1,
    end_slot: 64,
    state_root_before: "0".repeat(64),
    state_root_after:  "f".repeat(64),
  };
  const canon = canonicalize(artifact);
  const nodeHash = blake3.hash(Buffer.from(canon, "utf8"));
  const nodeHashHex = Buffer.from(nodeHash).toString("hex");

  const tmpDir = fs.mkdtempSync(path.join(require("node:os").tmpdir(), "zksl-"));
  const inPath = path.join(tmpDir, "artifact.json");
  const outPath = path.join(tmpDir, "proof.json");
  fs.writeFileSync(inPath, JSON.stringify(artifact));
  const rust = spawnSync("cargo", [
    "run", "-p", "prover", "--",
    "--input", inPath,
    "--out", outPath,
    "--agg-key", agg,
    "--chain-id", String(chainId),
    "--program_id", String(programId),
    "--seq", "1",
  ], { stdio: "inherit" });
  if (rust.status !== 0) fatal("prover run failed");
  const rustOut = JSON.parse(fs.readFileSync(outPath, "utf8"));
  const rustHashHex = rustOut.proof_hash;
  if (rustHashHex !== nodeHashHex) fatal(`proof_hash mismatch: node=${nodeHashHex} rust=${rustHashHex}`);
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ status: "ok", proof_hash: nodeHashHex }, null, 2));
}

main();


