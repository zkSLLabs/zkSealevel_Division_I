import express from "express";
import type { Request, Response } from "express";
import dotenv from "dotenv";
import { randomBytes } from "crypto";
import { hash as blake3hash } from "blake3";
import nacl from "tweetnacl";
import * as fs from "fs";
import { promises as fsp } from "fs";
import * as path from "path";
import { Client as PgClient } from "pg";
import { encodeAnchorProofArgsBorsh, encodeAnchorProofV2ArgsBorsh, i64le, u64le, canonicalize, buildDS } from "./crypto.js";
import { mapProgramError } from "./errors.js";
import { fetchConfig, fetchLastSeq } from "./onchain.js";
import { spawnSync } from "child_process";
import type { Commitment } from "@solana/web3.js";
import { signWithHsmEd25519 } from "./hsm.js";

dotenv.config({ path: process.cwd() + "/.env" });

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = parseInt(process.env.PORT || "8080", 10);
const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";
const PROGRAM_ID = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
const CHAIN_ID = BigInt(process.env.CHAIN_ID || "103");
const AGG_KEY_PATH = process.env.AGGREGATOR_KEYPAIR_PATH || "./keys/aggregator.json";
const ARTIFACT_DIR = process.env.ARTIFACT_DIR || "./orchestrator/data/artifacts";
const DATABASE_URL = process.env.DATABASE_URL || "postgres://postgres:postgres@localhost:5432/zksl";
const AGGREGATOR_HSM_URI = process.env.AGGREGATOR_HSM_URI || "";
const LOCAL_MODE = (process.env.LOCAL_MODE || "0") === "1";

function isStarkRequired(): boolean {
  return (process.env.REQUIRE_STARK ?? "1") !== "0";
}

type Artifact = Record<string, unknown> & {
  artifact_id?: string | undefined;
  start_slot?: number | undefined;
  end_slot?: number | undefined;
  artifact_len?: number | undefined;
  state_root_before?: string | undefined; // 32-byte hex
  state_root_after?: string | undefined;  // 32-byte hex
};

const artifacts = new Map<string, Artifact & { proof_hash?: string }>();

// Idempotency cache (24h TTL) per Complete_Architecture.md §6 and Master_Blueprint §22
const IDEMP_TTL_MS = 24 * 60 * 60 * 1000;
type CachedResponse = { status: number; body: unknown; ts: number };
const idempotencyCache = new Map<string, CachedResponse>();
let idemSetCounter = 0;
let localSeq: bigint = 0n;

function getIdemKey(req: Request): string | null {
  const raw = req.headers["idempotency-key"];
  const k = Array.isArray(raw) ? raw[0] : raw;
  if (!k) return null;
  const v = k.trim();
  return v.length > 0 ? v : null;
}

function enforceIdempotency(req: Request, res: Response, next: () => void) {
  if (req.method !== "POST") return next();
  const key = getIdemKey(req);
  if (!key) {
    res.status(400).json({ error: { code: "MissingIdempotencyKey", message: "Idempotency-Key header required", details: null } });
    return;
  }
  const existing = idempotencyCache.get(key);
  if (existing && Date.now() - existing.ts < IDEMP_TTL_MS) {
    res.status(existing.status).json(existing.body);
    return;
  }
  const originalJson = res.json.bind(res);
  res.json = (body: unknown) => {
    try {
      const sc = res.statusCode;
      idempotencyCache.set(key, { status: sc || 200, body, ts: Date.now() });
      if (++idemSetCounter % 100 === 0) {
        const now = Date.now();
        for (const [k, v] of idempotencyCache) if (now - v.ts >= IDEMP_TTL_MS) idempotencyCache.delete(k);
      }
    } catch (_) {
      // noop
    }
    return originalJson(body);
  };
  next();
}

app.use(enforceIdempotency);

function shouldUseV2(): boolean {
  // Operation-Ghost-Ship: Testnet must use v2 (CHAIN_ID=102), or explicit override
  return (process.env.CHAIN_ID || "") === "102" || (process.env.USE_V2 || "") === "1";
}

function loadAggregatorSecret(): Uint8Array {
  const raw = fs.readFileSync(AGG_KEY_PATH, { encoding: "utf8" });
  const parsed: unknown = JSON.parse(raw);
  if (Array.isArray(parsed) && parsed.length === 64) {
    return new Uint8Array(parsed);
  }
  if (typeof parsed === "object" && parsed !== null && "solana" in parsed) {
    const obj = parsed as { solana: unknown };
    if (Array.isArray(obj.solana) && obj.solana.length === 64) {
      return new Uint8Array(obj.solana);
    }
  }
  if (typeof parsed === "object" && parsed !== null && "secretKey" in parsed) {
    const obj = parsed as { secretKey: string };
    const hex = obj.secretKey;
    const bytes = Buffer.from(hex, "hex");
    if (bytes.length !== 64) throw new Error("secretKey must be 64-byte ed25519 seed+key in hex");
    return new Uint8Array(bytes);
  }
  throw new Error("AGGREGATOR_KEYPAIR_PATH invalid format");
}

// buildDS imported from ./crypto.ts

// Health
app.get("/health", (_req: Request, res: Response) => {
  res.json({ status: "ok", version: "0.1.0" });
});

// POST /prove: build canonical artifact and persist (stubbed prover integration)
app.post("/prove", async (req: Request, res: Response) => {
  const artifact = req.body as Artifact;
  if (!artifact || typeof artifact !== "object") {
    return res.status(400).json({ error: { code: "BadRequest", message: "invalid artifact", details: null } });
  }
  if (
    typeof artifact.start_slot !== "number" ||
    typeof artifact.end_slot !== "number" ||
    typeof artifact.state_root_before !== "string" ||
    typeof artifact.state_root_after !== "string" ||
    !isHex32(artifact.state_root_before) ||
    !isHex32(artifact.state_root_after)
  ) {
    return res.status(400).json({ error: { code: "BadRequest", message: "missing or invalid fields", details: { required: ["start_slot","end_slot","state_root_before","state_root_after"] } } });
  }
  if (artifact.end_slot < artifact.start_slot) {
    return res.status(400).json({ error: { code: "BadRequest", message: "end_slot must be >= start_slot", details: null } });
  }
  const window = artifact.end_slot - artifact.start_slot + 1;
  if (window > 2048) {
    return res.status(400).json({ error: { code: "BadRequest", message: "slot window exceeds MAX_SLOTS_PER_ARTIFACT", details: { max: 2048 } } });
  }
  let srb = normalizeHex32(artifact.state_root_before);
  let sra = normalizeHex32(artifact.state_root_after);
  const minimal = canonicalize({
    start_slot: artifact.start_slot,
    end_slot: artifact.end_slot,
    state_root_before: srb,
    state_root_after: sra,
  });
  const proofHashBytes = Buffer.from(blake3hash(Buffer.from(minimal, "utf8")));
  const proofHashHex = Buffer.from(proofHashBytes).toString("hex");
  const artifactId = uuidFromHash32(proofHashBytes);
  const canonical = canonicalize({
    artifact_id: artifactId,
    start_slot: artifact.start_slot,
    end_slot: artifact.end_slot,
    state_root_before: srb,
    state_root_after: sra,
  });
  const now = new Date();
  const y = String(now.getUTCFullYear());
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const dir = path.join(ARTIFACT_DIR, y, m, d);
  await ensureDir(dir);
  const target = path.join(dir, `${artifactId}.json`);
  const artifact_len = Buffer.byteLength(canonical, "utf8");
  if (artifact_len > 512 * 1024) {
    return res.status(400).json({ error: { code: "BadRequest", message: "artifact exceeds MAX_ARTIFACT_SIZE_BYTES", details: { max: 512 * 1024 } } });
  }
  await fsp.writeFile(target, Buffer.from(canonical, "utf8"));
  artifacts.set(artifactId, { artifact_id: artifactId, start_slot: artifact.start_slot, end_slot: artifact.end_slot, state_root_before: srb, state_root_after: sra, artifact_len, proof_hash: proofHashHex });
  // Optional STARK proof generation (Phase A): gated by REQUIRE_STARK env
  if (isStarkRequired()) {
    try {
      // Step 1: Generate witness from RPC (if not provided)
      const witnessPath = path.join(dir, `${artifactId}.witness.json`);
      const rpcUrl = RPC_URL || "https://api.devnet.solana.com";
      
      // Check if witness already exists, else generate
      if (!fs.existsSync(witnessPath)) {
        const witnessRes = spawnSync("prover", [
          "generate-witness",
          "--rpc", rpcUrl,
          "--start", String(artifact.start_slot),
          "--end", String(artifact.end_slot),
          "--out", witnessPath
        ], { stdio: "inherit" });
        
        if (witnessRes.status !== 0) {
          // Witness generation failed, fallback to provided state roots
          console.warn("Witness generation failed, using provided state roots");
        } else {
          // Load generated witness to get real state roots
          const witnessData = JSON.parse(fs.readFileSync(witnessPath, "utf8")) as { state_root_before?: string; state_root_after?: string };
          if (witnessData.state_root_before && witnessData.state_root_after) {
            // Update artifact with real state roots from witness
            srb = normalizeHex32(witnessData.state_root_before);
            sra = normalizeHex32(witnessData.state_root_after);
          }
        }
      }
      
      // Step 2: Generate STARK proof using witness-derived state roots
      const proofPath = path.join(dir, `${artifactId}.proof.json`);
      const r = spawnSync("prover", [
        "stark-prove",
        "--start", String(artifact.start_slot),
        "--end", String(artifact.end_slot),
        "--before", srb,
        "--after", sra,
        "--proof-hash", proofHashHex,
        "--out", proofPath
      ], { stdio: "inherit" });
      if (r.status !== 0) {
        return res.status(500).json({ error: { code: "StarkProveFailed", message: "prover stark-prove failed", details: null } });
      }
      res.json({ artifact_id: artifactId, proof_hash: proofHashHex, stark_proof_file: proofPath, witness_file: witnessPath });
      return;
    } catch (e) {
      return res.status(500).json({ error: { code: "StarkProveException", message: String(e), details: null } });
    }
  }
  res.json({ artifact_id: artifactId, proof_hash: proofHashHex });
});

// POST /artifact: accept canonical artifact JSON, compute proof_hash
app.post("/artifact", async (req: Request, res: Response) => {
  const artifact = req.body as Artifact;
  if (!artifact || typeof artifact !== "object") {
    return res.status(400).json({ error: { code: "BadRequest", message: "invalid artifact", details: null } });
  }
  // Minimal schema validation per Complete_Architecture.md §5
  if (
    typeof artifact.start_slot !== "number" ||
    typeof artifact.end_slot !== "number" ||
    typeof artifact.state_root_before !== "string" ||
    typeof artifact.state_root_after !== "string" ||
    !isHex32(artifact.state_root_before) ||
    !isHex32(artifact.state_root_after)
  ) {
    return res.status(400).json({ error: { code: "BadRequest", message: "missing or invalid fields", details: { required: ["start_slot","end_slot","state_root_before","state_root_after"] } } });
  }
  if (artifact.end_slot < artifact.start_slot) {
    return res.status(400).json({ error: { code: "BadRequest", message: "end_slot must be >= start_slot", details: null } });
  }
  const window = artifact.end_slot - artifact.start_slot + 1;
  if (window > 2048) {
    return res.status(400).json({ error: { code: "BadRequest", message: "slot window exceeds MAX_SLOTS_PER_ARTIFACT", details: { max: 2048 } } });
  }
  // Normalize hex fields to lowercase before hashing (determinism policy)
  const srb = normalizeHex32(artifact.state_root_before);
  const sra = normalizeHex32(artifact.state_root_after);

  // Compute proof_hash from canonical minimal fields (excluding artifact_id)
  const minimal = canonicalize({
    start_slot: artifact.start_slot,
    end_slot: artifact.end_slot,
    state_root_before: srb,
    state_root_after: sra,
  });
  const proofHashBytes = Buffer.from(blake3hash(Buffer.from(minimal, "utf8")));
  const proofHashHex = Buffer.from(proofHashBytes).toString("hex");
  const artifactId = uuidFromHash32(proofHashBytes);

  // Persist canonical JSON including artifact_id
  const canonical = canonicalize({
    artifact_id: artifactId,
    start_slot: artifact.start_slot,
    end_slot: artifact.end_slot,
    state_root_before: srb,
    state_root_after: sra,
  });
  const now = new Date();
  const y = String(now.getUTCFullYear());
  const m = String(now.getUTCMonth() + 1).padStart(2, "0");
  const d = String(now.getUTCDate()).padStart(2, "0");
  const dir = path.join(ARTIFACT_DIR, y, m, d);
  await ensureDir(dir);
  const target = path.join(dir, `${artifactId}.json`);
  const artifact_len = Buffer.byteLength(canonical, "utf8");
  if (artifact_len > 512 * 1024) {
    return res.status(400).json({ error: { code: "BadRequest", message: "artifact exceeds MAX_ARTIFACT_SIZE_BYTES", details: { max: 512 * 1024 } } });
  }
  await fsp.writeFile(target, Buffer.from(canonical, "utf8"));
  artifacts.set(artifactId, { artifact_id: artifactId, start_slot: artifact.start_slot, end_slot: artifact.end_slot, state_root_before: srb, state_root_after: sra, artifact_len, proof_hash: proofHashHex });
  res.json({ artifact_id: artifactId, proof_hash: proofHashHex });
});

// POST /anchor: build DS and submit (stub)
app.post("/anchor", async (req: Request, res: Response) => {
  await (async () => {
    const { artifact_id } = (req.body || {}) as { artifact_id?: string };
    if (!artifact_id) {
      return res.status(400).json({ error: { code: "BadRequest", message: "artifact_id required", details: null } });
    }
    let artifact = artifacts.get(artifact_id);
    if (!artifact) {
      // attempt to load from disk
      const loaded = await loadArtifactFromDisk(artifact_id);
      if (!loaded) return res.status(404).json({ error: { code: "NotFound", message: "artifact not found", details: null } });
      artifact = loaded;
      artifacts.set(artifact_id, artifact);
    }
    // Recompute proof_hash from minimal canonical fields (deterministic)
    const minimal = canonicalize({
      start_slot: artifact.start_slot,
      end_slot: artifact.end_slot,
      state_root_before: normalizeHex32(String(artifact.state_root_before || "")),
      state_root_after: normalizeHex32(String(artifact.state_root_after || "")),
    });
    const proofHash = blake3hash(Buffer.from(minimal, "utf8"));
    if (LOCAL_MODE) {
      const web3 = await import("@solana/web3.js");
      localSeq = localSeq + 1n;
      const seq = localSeq;
      const startSlot = BigInt(artifact.start_slot ?? 1);
      const endSlot = BigInt(artifact.end_slot ?? 1);
      const { ds, dsHash } = buildDS({
        chainId: CHAIN_ID,
        programId: new web3.PublicKey(PROGRAM_ID).toBytes(),
        proofHash,
        startSlot,
        endSlot,
        seq,
      });
      const secretKey = loadAggregatorSecret();
      const signature = nacl.sign.detached(ds, secretKey);
      const ds_hash = Buffer.from(dsHash).toString("hex");
      const aggregator_signature = Buffer.from(signature).toString("hex");
      return res.json({ aggregator_signature, ds_hash, transaction_id: `LOCAL-${Buffer.from(dsHash).toString("hex").slice(0, 16)}`, seq: Number(seq) });
    }
    // If STARK verification is required (Testnet/v2), verify sidecar proof file before proceeding
    let starkPiHash32: Buffer | null = null;
    let starkProofHash32: Buffer | null = null;
    if (isStarkRequired() || shouldUseV2()) {
      try {
        const proofPath = await findFileRecursive(ARTIFACT_DIR, `${artifact_id}.proof.json`, 4);
        if (!proofPath) throw new Error("missing sidecar STARK proof file");
        const r = spawnSync("prover", ["stark-verify", "--proof", proofPath], { stdio: "inherit" });
        if (r.status !== 0) {
          return res.status(400).json({ error: { code: "StarkVerifyFailed", message: "STARK proof verification failed", details: null } });
        }
        // Compute STARK hashes per Operation-Ghost-Ship §6.2
        const proofRaw = await fsp.readFile(proofPath, { encoding: "utf8" });
        const proofObj = JSON.parse(proofRaw) as { public_inputs?: unknown; proof_b64?: string };
        const proofBytes = Buffer.from(String(proofObj.proof_b64 || ""), "base64");
        const { dsHash } = buildDS({
          chainId: CHAIN_ID,
          programId: new (await import("@solana/web3.js")).PublicKey(PROGRAM_ID).toBytes(),
          proofHash,
          startSlot: BigInt(artifact.start_slot ?? 1),
          endSlot: BigInt(artifact.end_slot ?? 1),
          seq: (await fetchLastSeq(PROGRAM_ID, RPC_URL)) + 1n,
        });
        // Prefer North Star Route PI set if present in sidecar
        // Expected fields: c_in_hex, c_out_hex, h_b_hex, s_in (array), s_out (array)
        const pi = (proofObj as any).public_inputs as any;
        let piCanonical: string;
        if (pi && (pi.c_in_hex || pi.c_out_hex || pi.h_b_hex || pi.S_in || pi.S_out || pi.s_in || pi.s_out)) {
          const S_in = Array.isArray(pi.s_in ?? pi.S_in) ? (pi.s_in ?? pi.S_in).map((kv: any) => ({
            account: String(kv.account ?? ""),
            value: String(kv.value ?? ""),
          })) : [];
          const S_out = Array.isArray(pi.s_out ?? pi.S_out) ? (pi.s_out ?? pi.S_out).map((kv: any) => ({
            account: String(kv.account ?? ""),
            value: String(kv.value ?? ""),
          })) : [];
          const PI_payload = {
            C_in: String(pi.c_in_hex ?? pi.C_in ?? ""),
            C_out: String(pi.c_out_hex ?? pi.C_out ?? ""),
            H_B: String(pi.h_b_hex ?? pi.H_B ?? ""),
            S_in,
            S_out,
          };
          piCanonical = canonicalize(PI_payload);
        } else {
          // Backward-compatible minimal PI (binds DS as well)
          piCanonical = canonicalize({
            start_slot: artifact.start_slot,
            end_slot: artifact.end_slot,
            state_root_before: normalizeHex32(String(artifact.state_root_before || "")),
            state_root_after: normalizeHex32(String(artifact.state_root_after || "")),
            proof_hash: Buffer.from(proofHash).toString("hex"),
            ds_hash: Buffer.from(dsHash).toString("hex"),
          });
        }
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const blake3 = await import("blake3");
        starkPiHash32 = Buffer.from(blake3.hash(Buffer.from(piCanonical, "utf8")));
        starkProofHash32 = Buffer.from(blake3.hash(proofBytes));
      } catch (e) {
        return res.status(400).json({ error: { code: "StarkVerifyException", message: String(e), details: null } });
      }
    }
    const web3 = await import("@solana/web3.js");
    // Read aggregator state and compute next seq
    let lastSeq: bigint;
    try {
      lastSeq = await fetchLastSeq(PROGRAM_ID, RPC_URL);
    } catch (e) {
      return res.status(500).json({ error: { code: "FetchLastSeqFailed", message: String(e), details: null } });
    }
    const seq = lastSeq + 1n;
    const startSlot = BigInt(artifact.start_slot ?? 1);
    const endSlot = BigInt(artifact.end_slot ?? 1);
    // Fetch on-chain config and enforce CHAIN_ID match
    let cfg: { aggregator_pubkey: Uint8Array; next_aggregator_pubkey: Uint8Array; activation_seq: bigint; chain_id: bigint; };
    try {
      cfg = await fetchConfig(PROGRAM_ID, RPC_URL);
    } catch (e) {
      return res.status(400).json({ error: { code: "ConfigNotFound", message: String(e), details: null } });
    }
    if (cfg.chain_id !== CHAIN_ID) {
      return res.status(400).json({ error: { code: "ChainIdMismatch", message: `env CHAIN_ID=${CHAIN_ID} != on-chain ${cfg.chain_id}`, details: null } });
    }
    // Determine allowed aggregator pubkey for seq per activation_seq
    const allowedAgg = seq >= cfg.activation_seq ? cfg.next_aggregator_pubkey : cfg.aggregator_pubkey;
    const { ds, dsHash } = buildDS({
      chainId: CHAIN_ID,
      programId: new web3.PublicKey(PROGRAM_ID).toBytes(),
      proofHash,
      startSlot,
      endSlot,
      seq,
    });
    // Sign DS: HSM required on Testnet (CHAIN_ID=102)
    let signature: Uint8Array;
    if (shouldUseV2()) {
      if (!AGGREGATOR_HSM_URI) {
        return res.status(400).json({ error: { code: "HsmRequired", message: "AGGREGATOR_HSM_URI must be set on Testnet (v2)", details: null } });
      }
      signature = await signWithHsmEd25519(AGGREGATOR_HSM_URI, ds);
    } else {
      const secretKey = loadAggregatorSecret();
      signature = nacl.sign.detached(ds, secretKey);
      const aggKeypair = nacl.sign.keyPair.fromSecretKey(secretKey);
      const aggPub = new Uint8Array(aggKeypair.publicKey);
      if (!bytesEq(aggPub, allowedAgg)) {
        return res.status(400).json({ error: { code: "AggregatorKeyMismatch", message: "aggregator secret does not match allowed aggregator_pubkey", details: null } });
      }
    }
    const aggregator_signature = Buffer.from(signature).toString("hex");
    const ds_hash = Buffer.from(dsHash).toString("hex");
    try {
      // Prepare real args per spec
      const artifact_id_bytes = uuidToBytes(String(artifact.artifact_id || "")) || uuidToBytes(randomUuidV4());
      const state_root_before = hexTo32(normalizeHex32(String(artifact.state_root_before || "")));
      const state_root_after = hexTo32(normalizeHex32(String(artifact.state_root_after || "")));
      const timestamp = BigInt(Math.floor(Date.now() / 1000));
      const txid = shouldUseV2()
        ? await submitAnchorProofV2({
            rpcUrl: RPC_URL,
            programIdStr: PROGRAM_ID,
            ed25519Signature: signature,
            aggregatorPubkey: allowedAgg,
            ds,
            dsHash,
            proofHash,
            startSlot,
            endSlot,
            seq,
            artifactId: artifact_id_bytes,
            artifactLen: Number(artifact.artifact_len || 0),
            stateRootBefore: state_root_before,
            stateRootAfter: state_root_after,
            timestamp,
            starkPiHash32: starkPiHash32 ?? Buffer.alloc(32, 0),
            starkProofHash32: starkProofHash32 ?? Buffer.alloc(32, 0),
          })
        : await submitAnchorProofV1({
            rpcUrl: RPC_URL,
            programIdStr: PROGRAM_ID,
            ds,
            dsHash,
            proofHash,
            startSlot,
            endSlot,
            seq,
            aggregatorSecretKey: loadAggregatorSecret(),
            aggregatorPubkey: allowedAgg,
            artifactId: artifact_id_bytes,
            artifactLen: Number(artifact.artifact_len || 0),
            stateRootBefore: state_root_before,
            stateRootAfter: state_root_after,
            timestamp,
          });
      res.json({ aggregator_signature, ds_hash, transaction_id: txid });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error("/anchor failed:", e);
      const mapped = mapProgramError(e);
      res.status(mapped.http).json({ error: { code: mapped.code, message: mapped.message, details: mapped.details } });
    }
  })().catch((e) => {
    // eslint-disable-next-line no-console
    console.error("Unhandled /anchor error:", e);
    if (!(res as any).headersSent) {
      res.status(500).json({ error: { code: "Unhandled", message: String(e), details: null } });
    }
  });
});

// GET endpoints per Complete_Architecture.md
app.get("/proof/:artifact_id", async (req: Request, res: Response) => {
  const params = req.params;
  const id = String(params.artifact_id ?? "");
  const art = artifacts.get(id);
  if (LOCAL_MODE) {
    if (!art) return res.status(404).json({ error: { code: "NotFound", message: "artifact not found", details: null } });
    return res.json({ artifact: art, status: null });
  }
  const pg = new PgClient({ connectionString: DATABASE_URL });
  await pg.connect();
  const row = await pg.query("SELECT * FROM proofs WHERE artifact_id = $1 ORDER BY ts DESC LIMIT 1", [id]);
  await pg.end();
  if (!art && row.rows.length === 0) return res.status(404).json({ error: { code: "NotFound", message: "artifact not found", details: null } });
  const status = row.rows[0] ? { commitment_level: row.rows[0].commitment_level, txid: row.rows[0].txid, seq: row.rows[0].seq } : null;
  res.json({ artifact: art ?? null, status });
});

app.get("/validator/:pubkey", async (req: Request, res: Response) => {
  const params = req.params;
  const pk = String(params.pubkey ?? "");
  const pg = new PgClient({ connectionString: DATABASE_URL });
  await pg.connect();
  const row = await pg.query("SELECT * FROM validators WHERE pubkey = $1", [pk]);
  await pg.end();
  if (row.rows.length === 0) return res.status(404).json({ error: { code: "NotFound", message: "validator not found", details: null } });
  res.json({ validator: row.rows[0] });
});

// Avoid binding a real port when running under vitest or NODE_ENV=test
if (!process.env.VITEST && process.env.NODE_ENV !== "test") {
  app.listen(PORT, () => {
    // eslint-disable-next-line no-console
    console.log(`orchestrator listening on :${PORT}`);
  });
}

export { app };

// ============== Solana TX submission (Ed25519 preflight + ComputeBudget) ==============
async function submitAnchorProofV1(params: {
  rpcUrl: string;
  programIdStr: string;
  ds: Uint8Array;
  dsHash: Uint8Array;
  proofHash: Uint8Array;
  startSlot: bigint;
  endSlot: bigint;
  seq: bigint;
  aggregatorSecretKey: Uint8Array;
  aggregatorPubkey: Uint8Array; // allowed key for seq
  artifactId: Uint8Array; // 16 bytes
  artifactLen: number; // u32
  stateRootBefore: Uint8Array; // 32 bytes
  stateRootAfter: Uint8Array;  // 32 bytes
  timestamp: bigint; // i64
}): Promise<string> {
  // Lazy import to avoid hard type coupling to local shims
  const web3 = await import("@solana/web3.js");
  const connection = new web3.Connection(params.rpcUrl, {
    commitment: (process.env.MIN_FINALITY_COMMITMENT as Commitment) || "finalized",
  });
  // Load fee payer from env or default Solana keypair path; do NOT require aggregator to be a tx signer
  const feePayerPath = process.env.FEE_PAYER_KEYPAIR_PATH
    || (process.env.USERPROFILE ? path.join(process.env.USERPROFILE, ".config", "solana", "id.json") : undefined)
    || "./keys/sol_agg.json";
  let payer: typeof web3.Keypair.prototype;
  try {
    const raw = fs.readFileSync(feePayerPath, { encoding: "utf8" });
    const arr = JSON.parse(raw) as number[];
    payer = web3.Keypair.fromSecretKey(Uint8Array.from(arr));
  } catch (e) {
    throw new Error(`FeePayerLoadFailed: ${String(e)}`);
  }

  // TypeScript doesn't have ComputeBudgetProgram in web3.js types, so we need to access it via dynamic import
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
  const ComputeBudgetProgram = (web3 as any).ComputeBudgetProgram;
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access
  const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }) as typeof web3.TransactionInstruction.prototype;
  const ed25519Ix = web3.Ed25519Program.createInstructionWithPublicKey({
    publicKey: Buffer.from(params.aggregatorPubkey),
    message: Buffer.from(params.ds),
    signature: nacl.sign.detached(params.ds, params.aggregatorSecretKey),
  });

  const proofHash32 = Buffer.from(params.proofHash);
  const dsHash32 = Buffer.from(params.dsHash);
  const startLe = u64le(params.startSlot);
  const endLe = u64le(params.endSlot);
  const seqLe = u64le(params.seq);

  // eslint-disable-next-line no-console
  console.log("submitAnchorProof: proof_hash hex:", proofHash32.toString("hex"));
  // eslint-disable-next-line no-console
  console.log("submitAnchorProof: seq:", params.seq.toString());

  const data = encodeAnchorProofArgsBorsh({
    artifactId: params.artifactId,
    proofHash32,
    seqLe,
    startLe,
    endLe,
    artifactLen: params.artifactLen,
    stateRootBefore: params.stateRootBefore,
    stateRootAfter: params.stateRootAfter,
    aggregatorPubkey: params.aggregatorPubkey,
    timestampLe: i64le(params.timestamp),
    dsHash32,
  });

  const programId = new web3.PublicKey(params.programIdStr);
  const configPda = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("config")],
    programId,
  )[0];

  const aggregatorStatePda = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("aggregator")],
    programId,
  )[0];

  const rangeStatePda = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("range")],
    programId,
  )[0];

  const proofRecordPda = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("proof"), proofHash32, seqLe],
    programId,
  )[0];
  
  // eslint-disable-next-line no-console
  console.log("submitAnchorProof: derived proofRecordPda:", proofRecordPda.toString());

  // SYSVAR_INSTRUCTIONS_PUBKEY is available in web3.js but may not be in types
  // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access
  const SYSVAR_INSTRUCTIONS_PUBKEY = (web3 as any).SYSVAR_INSTRUCTIONS_PUBKEY as typeof web3.PublicKey.prototype;

  const keys = [
    { pubkey: payer.publicKey, isSigner: true, isWritable: true },
    { pubkey: configPda, isSigner: false, isWritable: true },
    { pubkey: aggregatorStatePda, isSigner: false, isWritable: true },
    { pubkey: rangeStatePda, isSigner: false, isWritable: true },
    { pubkey: proofRecordPda, isSigner: false, isWritable: true },
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
  ];

  // eslint-disable-next-line no-console
  console.log("anchor keys lens:", keys.length);
  for (let i = 0; i < keys.length; i++) {
    const k = keys[i];
    if (k) {
      // eslint-disable-next-line no-console
      console.log("key[", i, "]", {
        hasPub: !!k.pubkey,
        isSigner: k.isSigner,
        isWritable: k.isWritable,
        pub: k.pubkey?.toString?.(),
      });
    }
  }
  const ix = new web3.TransactionInstruction({ keys, programId, data });
  const tx = new web3.Transaction();
  // eslint-disable-next-line no-console
  console.log("anchor ix pid:", programId.toString());
  tx.add(computeIx);
  tx.add(ed25519Ix);
  tx.add(ix);

  const latest = await connection.getLatestBlockhash();
  tx.recentBlockhash = latest.blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  const sig = await web3.sendAndConfirmTransaction(connection, tx, [payer]);
  return sig;
}

async function submitAnchorProofV2(params: {
  rpcUrl: string;
  programIdStr: string;
  ed25519Signature: Uint8Array;
  aggregatorPubkey: Uint8Array;
  ds: Uint8Array;
  dsHash: Uint8Array;
  proofHash: Uint8Array;
  startSlot: bigint;
  endSlot: bigint;
  seq: bigint;
  artifactId: Uint8Array;
  artifactLen: number;
  stateRootBefore: Uint8Array;
  stateRootAfter: Uint8Array;
  timestamp: bigint;
  starkPiHash32: Buffer;
  starkProofHash32: Buffer;
}): Promise<string> {
  const web3 = await import("@solana/web3.js");
  const connection = new web3.Connection(params.rpcUrl, {
    commitment: (process.env.MIN_FINALITY_COMMITMENT as Commitment) || "finalized",
  });
  const feePayerPath = process.env.FEE_PAYER_KEYPAIR_PATH
    || (process.env.USERPROFILE ? path.join(process.env.USERPROFILE, ".config", "solana", "id.json") : undefined)
    || "./keys/sol_agg.json";
  const raw = fs.readFileSync(feePayerPath, { encoding: "utf8" });
  const arr = JSON.parse(raw) as number[];
  const payer = web3.Keypair.fromSecretKey(Uint8Array.from(arr));
  const ComputeBudgetProgram = (web3 as any).ComputeBudgetProgram;
  const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 }) as typeof web3.TransactionInstruction.prototype;
  const ed25519Ix = web3.Ed25519Program.createInstructionWithPublicKey({
    publicKey: Buffer.from(params.aggregatorPubkey),
    message: Buffer.from(params.ds),
    signature: Buffer.from(params.ed25519Signature),
  });
  const proofHash32 = Buffer.from(params.proofHash);
  const dsHash32 = Buffer.from(params.dsHash);
  const startLe = u64le(params.startSlot);
  const endLe = u64le(params.endSlot);
  const seqLe = u64le(params.seq);
  const data = encodeAnchorProofV2ArgsBorsh({
    artifactId: params.artifactId,
    proofHash32,
    seqLe,
    startLe,
    endLe,
    artifactLen: params.artifactLen,
    stateRootBefore: params.stateRootBefore,
    stateRootAfter: params.stateRootAfter,
    aggregatorPubkey: params.aggregatorPubkey,
    timestampLe: i64le(params.timestamp),
    dsHash32,
    starkPiHash32: params.starkPiHash32,
    starkProofHash32: params.starkProofHash32,
  });
  const programId = new web3.PublicKey(params.programIdStr);
  const configPda = web3.PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], programId)[0];
  const aggregatorStatePda = web3.PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("aggregator")], programId)[0];
  const rangeStatePda = web3.PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("range")], programId)[0];
  const proofRecordPda = web3.PublicKey.findProgramAddressSync(
    [Buffer.from("zksl"), Buffer.from("proof2"), proofHash32, seqLe],
    programId,
  )[0];
  const SYSVAR_INSTRUCTIONS_PUBKEY = (web3 as any).SYSVAR_INSTRUCTIONS_PUBKEY as typeof web3.PublicKey.prototype;
  const keys = [
    { pubkey: payer.publicKey, isSigner: true, isWritable: true },
    { pubkey: configPda, isSigner: false, isWritable: true },
    { pubkey: aggregatorStatePda, isSigner: false, isWritable: true },
    { pubkey: rangeStatePda, isSigner: false, isWritable: true },
    { pubkey: proofRecordPda, isSigner: false, isWritable: true },
    { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    { pubkey: web3.SystemProgram.programId, isSigner: false, isWritable: false },
  ];
  const ix = new web3.TransactionInstruction({ keys, programId, data });
  const tx = new web3.Transaction();
  tx.add(computeIx);
  tx.add(ed25519Ix);
  tx.add(ix);
  const latest = await connection.getLatestBlockhash();
  tx.recentBlockhash = latest.blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  const sig = await web3.sendAndConfirmTransaction(connection, tx, [payer]);
  return sig;
}

// (moved Borsh encoder and LE helpers to crypto.ts)

// mapProgramError moved to errors.ts

// ============== Canonical JSON (JCS-like) ==============
// canonicalize imported from ./crypto.ts

async function ensureDir(dir: string): Promise<void> {
  try {
    await fsp.mkdir(dir, { recursive: true });
  } catch (_) {
    // ignore
  }
}

// ============== On-chain Config helpers are imported from ./onchain.ts ==============

// ============== Utils ==============
function isHex32(s: string): boolean { return /^[0-9a-fA-F]{64}$/.test(s); }
function hexTo32(s: string): Uint8Array { return new Uint8Array(Buffer.from(s, "hex")); }
function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}
function randomUuidV4(): string {
  const b = randomBytes(16);
  b.writeUInt8((b.readUInt8(6) & 0x0f) | 0x40, 6); // version 4
  b.writeUInt8((b.readUInt8(8) & 0x3f) | 0x80, 8); // variant 10xx
  const hex = b.toString("hex");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}
function uuidToBytes(u: string): Uint8Array {
  // Accept UUID v4 string; parse hex sans dashes
  const hex = u.replace(/-/g, "");
  if (hex.length !== 32) {
    // generate random if malformed
    return new Uint8Array(Buffer.from(randomUuidV4().replace(/-/g, ""), "hex"));
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

function normalizeHex32(s: string): string {
  if (!isHex32(s)) throw new Error("invalid 32-byte hex");
  return s.toLowerCase();
}

function uuidFromHash32(hash: Uint8Array): string {
  if (hash.length < 16) throw new Error("hash must be at least 16 bytes");
  const b = Buffer.from(hash.subarray(0, 16));
  b.writeUInt8((b.readUInt8(6) & 0x0f) | 0x40, 6); // version 4
  b.writeUInt8((b.readUInt8(8) & 0x3f) | 0x80, 8); // variant 10xx
  const hex = b.toString("hex");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

async function loadArtifactFromDisk(artifactId: string): Promise<(Artifact & { proof_hash?: string }) | null> {
  try {
    const p = await findFileRecursive(ARTIFACT_DIR, `${artifactId}.json`, 4);
    if (!p) return null;
    const raw = await fsp.readFile(p, { encoding: "utf8" });
    const obj = JSON.parse(raw) as Artifact;
    return { ...obj };
  } catch (_) {
    return null;
  }
}

async function findFileRecursive(dir: string, fileName: string, maxDepth: number): Promise<string | null> {
  if (maxDepth < 0) return null;
  const entries = await fsp.readdir(dir, { withFileTypes: true }).catch(() => []);
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isFile() && e.name === fileName) return p;
    if (e.isDirectory()) {
      const f = await findFileRecursive(p, fileName, maxDepth - 1);
      if (f) return f;
    }
  }
  return null;
}

// fetchLastSeq is imported from ./onchain.ts


