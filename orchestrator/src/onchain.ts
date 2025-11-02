export async function fetchConfig(programIdStr: string, rpcUrl: string): Promise<{
  aggregator_pubkey: Uint8Array;
  next_aggregator_pubkey: Uint8Array;
  activation_seq: bigint;
  chain_id: bigint;
}> {
  const web3 = await import("@solana/web3.js");
  const programId = new (web3 as any).PublicKey(programIdStr);
  const connection = new (web3 as any).Connection(rpcUrl, { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
  const pda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], programId)[0];
  const acc = await connection.getAccountInfo(pda, { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
  if (!acc) throw new Error("config account not found");
  const data: Buffer = acc.data as Buffer;
  let off = 8 + 32 + 32; // zksl_mint + admin
  const aggregator_pubkey = data.subarray(off, off + 32); off += 32;
  const next_aggregator_pubkey = data.subarray(off, off + 32); off += 32;
  const activation_seq = data.readBigUInt64LE(off); off += 8;
  const chain_id = data.readBigUInt64LE(off); off += 8;
  return {
    aggregator_pubkey: new Uint8Array(aggregator_pubkey),
    next_aggregator_pubkey: new Uint8Array(next_aggregator_pubkey),
    activation_seq,
    chain_id,
  };
}

export async function fetchLastSeq(programIdStr: string, rpcUrl: string): Promise<bigint> {
  const web3 = await import("@solana/web3.js");
  const programId = new (web3 as any).PublicKey(programIdStr);
  const connection = new (web3 as any).Connection(rpcUrl, { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
  const pda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("aggregator")], programId)[0];
  const acc = await connection.getAccountInfo(pda, { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
  if (!acc) return 0n;
  const data: Buffer = acc.data as Buffer;
  let off = 8 + 32; // skip discriminator + aggregator_pubkey
  const lastSeq = data.readBigUInt64LE(off);
  return lastSeq;
}


