import * as bs58 from "bs58";

export interface DecodedProofRecord {
  artifact_id: string;
  start_slot: bigint;
  end_slot: bigint;
  proof_hash: Buffer;
  artifact_len: number;
  state_root_before: Buffer;
  state_root_after: Buffer;
  submitted_by: string;
  aggregator_pubkey: string;
  timestamp: bigint;
  seq: bigint;
  ds_hash: Buffer;
}

export interface DecodedValidatorRecord {
  pubkey: string;
  escrow: string;
  lock_ts: number;
  status: "Active" | "Unlocked";
  num_accepts: string;
}

export function decodeProofRecord(data: Buffer): DecodedProofRecord {
  let o = 8; // skip discriminator
  const artifactId = data.subarray(o, o + 16); o += 16;
  const start = data.readBigUInt64LE(o); o += 8;
  const end = data.readBigUInt64LE(o); o += 8;
  const proofHash = data.subarray(o, o + 32); o += 32;
  const artLen = data.readUInt32LE(o); o += 4;
  const srb = data.subarray(o, o + 32); o += 32;
  const sra = data.subarray(o, o + 32); o += 32;
  const submittedBy = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const aggregator = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const ts = data.readBigInt64LE(o); o += 8;
  const seq = data.readBigUInt64LE(o); o += 8;
  const dsHash = data.subarray(o, o + 32); o += 32;
  return {
    artifact_id: uuidFrom16(artifactId),
    start_slot: start,
    end_slot: end,
    proof_hash: Buffer.from(proofHash),
    artifact_len: artLen,
    state_root_before: Buffer.from(srb),
    state_root_after: Buffer.from(sra),
    submitted_by: submittedBy,
    aggregator_pubkey: aggregator,
    timestamp: ts,
    seq,
    ds_hash: Buffer.from(dsHash),
  };
}

export function decodeValidatorRecord(data: Buffer): DecodedValidatorRecord {
  let o = 8; // skip discriminator
  const validator = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const escrow = bs58.encode(data.subarray(o, o + 32)); o += 32;
  const lock_ts = Number(data.readBigInt64LE(o)); o += 8;
  const status_u8 = data.readUInt8(o); o += 1;
  const status = status_u8 === 0 ? "Active" : "Unlocked";
  const num_accepts = data.readBigUInt64LE(o).toString(); o += 8;
  return { pubkey: validator, escrow, lock_ts, status, num_accepts };
}

export function uuidFrom16(b: Buffer): string {
  const hex = b.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}


