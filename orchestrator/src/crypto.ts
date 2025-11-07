import { hash as blake3hash } from "blake3";
import { createHash } from "node:crypto";

export function buildDS(params: {
  chainId: bigint;
  programId: Uint8Array;
  proofHash: Uint8Array;
  startSlot: bigint;
  endSlot: bigint;
  seq: bigint;
}): { ds: Uint8Array; dsHash: Uint8Array } {
  const enc64 = (n: bigint) => {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(n);
    return b;
  };
  const ds = Buffer.concat([
    Buffer.from("zKSL/anchor/v1", "utf8"),
    enc64(params.chainId),
    Buffer.from(params.programId),
    Buffer.from(params.proofHash),
    enc64(params.startSlot),
    enc64(params.endSlot),
    enc64(params.seq),
  ]);
  const dsHash = blake3hash(ds);
  return { ds: new Uint8Array(ds), dsHash: new Uint8Array(dsHash) };
}

export function canonicalize(value: unknown): string {
  return stringifyCanonical(value);
  function stringifyCanonical(v: unknown): string {
    if (v === null) return "null";
    const t = typeof v;
    if (t === "number" || t === "boolean" || t === "string") return JSON.stringify(v);
    if (Array.isArray(v)) return "[" + (v as unknown[]).map(stringifyCanonical).join(",") + "]";
    if (t === "object") {
      const obj = v as Record<string, unknown>;
      const entries = Object.keys(obj)
        .filter((k) => obj[k] !== undefined && k !== "__proto__" && k !== "constructor" && k !== "prototype")
        .sort()
        .map((k) => JSON.stringify(k) + ":" + stringifyCanonical(obj[k]));
      return "{" + entries.join(",") + "}";
    }
    return JSON.stringify(v);
  }
}

export function isHex32(s: string): boolean { return /^[0-9a-fA-F]{64}$/.test(s); }
export function normalizeHex32(s: string): string {
  if (!isHex32(s)) throw new Error("invalid 32-byte hex");
  return s.toLowerCase();
}

export function uuidFromHash32(hash: Uint8Array): string {
  if (hash.length < 16) throw new Error("hash must be at least 16 bytes");
  const b = Buffer.from(hash.subarray(0, 16));
  // set version 4 (0100) in the high nibble of byte 6
  b.writeUInt8((b.readUInt8(6) & 0x0f) | 0x40, 6);
  // set variant 10xx in the high bits of byte 8
  b.writeUInt8((b.readUInt8(8) & 0x3f) | 0x80, 8);
  const hex = b.toString("hex");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}

export function sha256_8(s: string): Buffer {
  const h = createHash("sha256").update(s, "utf8").digest();
  return h.subarray(0, 8);
}

export function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}

export function i64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(n);
  return b;
}

export function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n >>> 0);
  return b;
}

export function encodeAnchorProofArgsBorsh(params: {
  artifactId: Uint8Array;
  proofHash32: Buffer;
  seqLe: Buffer;
  startLe: Buffer;
  endLe: Buffer;
  artifactLen: number;
  stateRootBefore: Uint8Array;
  stateRootAfter: Uint8Array;
  aggregatorPubkey: Uint8Array;
  timestampLe: Buffer;
  dsHash32: Buffer;
}): Buffer {
  const disc = sha256_8("global:anchor_proof");
  // Match Rust function arg order: artifact_id, proof_hash, seq, start_slot, end_slot, artifact_len, state_root_before, state_root_after, aggregator_pubkey, timestamp, ds_hash
  const payload = Buffer.concat([
    Buffer.from(params.artifactId),       // arg 0
    params.proofHash32,                    // arg 1
    params.seqLe,                          // arg 2
    params.startLe,                        // arg 3
    params.endLe,                          // arg 4
    u32le(params.artifactLen),            // arg 5
    Buffer.from(params.stateRootBefore),  // arg 6
    Buffer.from(params.stateRootAfter),   // arg 7
    Buffer.from(params.aggregatorPubkey), // arg 8
    params.timestampLe,                    // arg 9
    params.dsHash32,                       // arg 10
  ]);
  return Buffer.concat([disc, payload]);
}


