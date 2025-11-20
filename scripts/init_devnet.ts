import { Connection, PublicKey, Keypair, SystemProgram, Transaction, TransactionInstruction, ComputeBudgetProgram, sendAndConfirmTransaction } from "@solana/web3.js";
import fs from "fs";
import nacl from "tweetnacl";
import { createHash } from "crypto";

function loadEnvFile(path: string) {
  try {
    const raw = fs.readFileSync(path, { encoding: "utf8" });
    for (const line of raw.split(/\r?\n/)) {
      if (!line || line.startsWith("#")) continue;
      const idx = line.indexOf("=");
      if (idx <= 0) continue;
      const k = line.slice(0, idx).trim();
      const v = line.slice(idx + 1).trim();
      if (k.length > 0) process.env[k] = v;
    }
  } catch {
    // ignore
  }
}

function sha256_8(s: string): Buffer {
  return createHash("sha256").update(s, "utf8").digest().subarray(0, 8);
}

function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}

function readKeypair(path: string): Keypair {
  const raw = fs.readFileSync(path, { encoding: "utf8" });
  const arr = JSON.parse(raw) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(arr));
}

function readAggPubkey(path: string): Uint8Array {
  const raw = fs.readFileSync(path, { encoding: "utf8" });
  const parsed = JSON.parse(raw) as any;
  let sec: Uint8Array;
  if (Array.isArray(parsed) && parsed.length === 64) {
    sec = Uint8Array.from(parsed);
  } else if (typeof parsed === "object" && parsed.secretKey) {
    const hex = String(parsed.secretKey);
    if (hex.length !== 128) throw new Error("agg-key secretKey must be 64-byte hex");
    sec = Uint8Array.from(Buffer.from(hex, "hex"));
  } else {
    throw new Error("Invalid aggregator key format");
  }
  const kp = nacl.sign.keyPair.fromSecretKey(sec);
  return new Uint8Array(kp.publicKey);
}

async function main() {
  loadEnvFile(process.cwd() + "/.env");
  const RPC = process.env.RPC_URL || "https://api.devnet.solana.com";
  const PROGRAM_ID_STR = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
  if (!PROGRAM_ID_STR) throw new Error("PROGRAM_ID_VALIDATOR_LOCK missing");
  const PROGRAM_ID = new PublicKey(PROGRAM_ID_STR);

  const payerPath = process.env.FEE_PAYER_KEYPAIR_PATH
    || (process.env.USERPROFILE ? `${process.env.USERPROFILE}/.config/solana/id.json` : undefined)
    || "./keys/sol_agg.json";
  const payer = readKeypair(payerPath);

  const conn = new Connection(RPC, { commitment: (process.env.MIN_FINALITY_COMMITMENT as any) || "finalized" });

  // Derive PDAs
  const [configPda] = PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], PROGRAM_ID);
  const [aggregatorStatePda] = PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("aggregator")], PROGRAM_ID);
  const [rangeStatePda] = PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("range")], PROGRAM_ID);

  // 1) init_state
  {
    const disc = sha256_8("global:init_state");
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: aggregatorStatePda, isSigner: false, isWritable: true },
        { pubkey: rangeStatePda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: disc,
    });
    const tx = new Transaction().add(ix);
    const { blockhash } = await conn.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = payer.publicKey;
    tx.sign(payer);
    const sig = await sendAndConfirmTransaction(conn, tx, [payer], { commitment: (process.env.MIN_FINALITY_COMMITMENT as any) || "finalized" });
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ init_state_txid: sig }, null, 2));
  }

  // 2) initialize(Config)
  {
    const mintStr = process.env.ZKSL_MINT || "";
    if (!mintStr) throw new Error("Set ZKSL_MINT in .env for initialize()");
    const mint = new PublicKey(mintStr);

    const aggKeyPath = process.env.AGGREGATOR_KEYPAIR_PATH || "./keys/aggregator.json";
    const aggPub = readAggPubkey(aggKeyPath);
    const disc = sha256_8("global:initialize");
    const payload = Buffer.concat([
      Buffer.from(aggPub), // aggregator_pubkey
      Buffer.from(aggPub), // next_aggregator_pubkey
      u64le(1n),           // activation_seq
      u64le(BigInt(process.env.CHAIN_ID || "103")), // chain_id
    ]);
    const data = Buffer.concat([disc, payload]);
    const computeIx = ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 });
    const ix = new TransactionInstruction({
      programId: PROGRAM_ID,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },  // payer
        { pubkey: payer.publicKey, isSigner: false, isWritable: false },// admin
        { pubkey: mint, isSigner: false, isWritable: false },           // zksl_mint
        { pubkey: configPda, isSigner: false, isWritable: true },       // config
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    const tx = new Transaction().add(computeIx).add(ix);
    const { blockhash } = await conn.getLatestBlockhash();
    tx.recentBlockhash = blockhash;
    tx.feePayer = payer.publicKey;
    tx.sign(payer);
    const sig = await sendAndConfirmTransaction(conn, tx, [payer], { commitment: (process.env.MIN_FINALITY_COMMITMENT as any) || "finalized" });
    // eslint-disable-next-line no-console
    console.log(JSON.stringify({ initialize_txid: sig }, null, 2));
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});


