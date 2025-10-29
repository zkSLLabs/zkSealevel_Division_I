import { hash as blake3hash } from "blake3";

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
    if (t === "number" || t === "boolean" || t === "string") return JSON.stringify(v as never);
    if (Array.isArray(v)) return "[" + (v as unknown[]).map(stringifyCanonical).join(",") + "]";
    if (t === "object") {
      const obj = v as Record<string, unknown>;
      const entries = Object.keys(obj)
        .filter((k) => (obj as Record<string, unknown>)[k] !== undefined)
        .sort()
        .map((k) => JSON.stringify(k) + ":" + stringifyCanonical(obj[k]));
      return "{" + entries.join(",") + "}";
    }
    return JSON.stringify(v as never);
  }
}

export function isHex32(s: string): boolean { return /^[0-9a-fA-F]{64}$/.test(s); }
export function normalizeHex32(s: string): string {
  if (!isHex32(s)) throw new Error("invalid 32-byte hex");
  return s.toLowerCase();
}

export function uuidFromHash32(hash: Uint8Array): string {
  const b = Buffer.from(hash.subarray(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const hex = b.toString("hex");
  return `${hex.slice(0,8)}-${hex.slice(8,12)}-${hex.slice(12,16)}-${hex.slice(16,20)}-${hex.slice(20)}`;
}


