// eslint-disable-next-line @typescript-eslint/no-var-requires
const dotenv = require("dotenv");
dotenv.config({ path: process.cwd() + "/.env" });

import { Command } from "commander";
import { randomUUID } from "node:crypto";

async function postJson(url: string, body: unknown, idem?: string): Promise<unknown> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (idem) headers["Idempotency-Key"] = idem;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { status: res.status, body: text }; }
}
function sha256_8(s: string): Buffer {
  const crypto = require("node:crypto");
  const h = crypto.createHash("sha256").update(s, "utf8").digest();
  return h.subarray(0, 8);
}

async function main() {
  const program = new Command();
  program
    .name("zksl")
    .description("zkSealevel CLI")
    .version("0.1.0");

  program.command("prove")
    .requiredOption("--input <PATH>")
    .requiredOption("--out <PATH>")
    .action(async () => {
      // Placeholder; real prover steps via Rust binary
      // eslint-disable-next-line no-console
      console.log("prove stub");
    });

  program.command("anchor")
    .requiredOption("--artifact <ID>")
    .action(async (opts) => {
      const base = process.env.ORCH_URL || "http://localhost:8080";
      const resp = await postJson(`${base}/anchor`, { artifact_id: opts.artifact }, randomUUID());
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(resp, null, 2));
    });

  program.command("status")
    .requiredOption("--artifact <ID>")
    .action(async (opts) => {
      const base = process.env.ORCH_URL || "http://localhost:8080";
      const res = await fetch(`${base}/proof/${encodeURIComponent(opts.artifact)}`);
      const body = await res.json();
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(body, null, 2));
    });

  program.command("status-validator")
    .requiredOption("--pubkey <PUBKEY>")
    .action(async (opts) => {
      const base = process.env.ORCH_URL || "http://localhost:8080";
      const res = await fetch(`${base}/validator/${encodeURIComponent(opts.pubkey)}`);
      const body = await res.json();
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(body, null, 2));
    });

  program.command("register")
    .requiredOption("--keypair <PATH>")
    .requiredOption("--mint <MINT>")
    .action(async (opts) => {
      const web3 = await import("@solana/web3.js");
      const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
      if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");
      const conn = new (web3 as any).Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new (web3 as any).PublicKey(programIdStr);
      const zkslMint = new (web3 as any).PublicKey(opts.mint);
      // Detect token program (Token or Token-2022) from mint owner
      const mintAcc = await conn.getAccountInfo(zkslMint);
      if (!mintAcc) throw new Error("Mint account not found");
      const tokenProgramId = new (web3 as any).PublicKey(mintAcc.owner);
      const payer = readKeypair(opts.keypair, web3);

      const configPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], programId)[0];
      const validatorRecordPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("validator"), payer.publicKey.toBytes()], programId)[0];
      const escrowAuthorityPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("escrow"), payer.publicKey.toBytes()], programId)[0];
      const ASSOCIATED_TOKEN_PROGRAM_ID = new (web3 as any).PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
      const validatorAta = (web3 as any).PublicKey.findProgramAddressSync([
        payer.publicKey.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID)[0];
      const escrowAta = (web3 as any).PublicKey.findProgramAddressSync([
        escrowAuthorityPda.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID)[0];

      const discriminator = sha256_8("global:register_validator");
      const data = discriminator; // no args
      const keys = [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: zkslMint, isSigner: false, isWritable: false },
        { pubkey: configPda, isSigner: false, isWritable: true },
        { pubkey: validatorRecordPda, isSigner: false, isWritable: true },
        { pubkey: escrowAuthorityPda, isSigner: false, isWritable: false },
        { pubkey: escrowAta, isSigner: false, isWritable: true },
        { pubkey: validatorAta, isSigner: false, isWritable: true },
        { pubkey: tokenProgramId, isSigner: false, isWritable: false },
        { pubkey: ASSOCIATED_TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        { pubkey: (web3 as any).SystemProgram.programId, isSigner: false, isWritable: false },
      ];
      const ix = new (web3 as any).TransactionInstruction({ keys, programId, data });
      const computeIx = (web3 as any).ComputeBudgetProgram?.setComputeUnitLimit
        ? (web3 as any).ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })
        : null;
      const tx = new (web3 as any).Transaction();
      if (computeIx) tx.add(computeIx);
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = payer.publicKey;
      tx.sign(payer);
      const sig = await (web3 as any).sendAndConfirmTransaction(conn, tx, [payer], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ txid: sig }, null, 2));
    });

  program.command("unlock")
    .requiredOption("--keypair <PATH>")
    .requiredOption("--mint <MINT>")
    .action(async (opts) => {
      const web3 = await import("@solana/web3.js");
      const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
      if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");
      const conn = new (web3 as any).Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new (web3 as any).PublicKey(programIdStr);
      const zkslMint = new (web3 as any).PublicKey(opts.mint);
      const mintAcc = await conn.getAccountInfo(zkslMint);
      if (!mintAcc) throw new Error("Mint account not found");
      const tokenProgramId = new (web3 as any).PublicKey(mintAcc.owner);
      const payer = readKeypair(opts.keypair, web3);

      const configPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], programId)[0];
      const validatorRecordPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("validator"), payer.publicKey.toBytes()], programId)[0];
      const escrowAuthorityPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("escrow"), payer.publicKey.toBytes()], programId)[0];
      const ASSOCIATED_TOKEN_PROGRAM_ID = new (web3 as any).PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
      const validatorAta = (web3 as any).PublicKey.findProgramAddressSync([
        payer.publicKey.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID)[0];
      const escrowAta = (web3 as any).PublicKey.findProgramAddressSync([
        escrowAuthorityPda.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID)[0];

      const discriminator = sha256_8("global:unlock_validator");
      const data = discriminator; // no args
      const keys = [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: zkslMint, isSigner: false, isWritable: false },
        { pubkey: configPda, isSigner: false, isWritable: true },
        { pubkey: validatorRecordPda, isSigner: false, isWritable: true },
        { pubkey: escrowAuthorityPda, isSigner: false, isWritable: false },
        { pubkey: escrowAta, isSigner: false, isWritable: true },
        { pubkey: validatorAta, isSigner: false, isWritable: true },
        { pubkey: tokenProgramId, isSigner: false, isWritable: false },
      ];
      const ix = new (web3 as any).TransactionInstruction({ keys, programId, data });
      const computeIx = (web3 as any).ComputeBudgetProgram?.setComputeUnitLimit
        ? (web3 as any).ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })
        : null;
      const tx = new (web3 as any).Transaction();
      if (computeIx) tx.add(computeIx);
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = payer.publicKey;
      tx.sign(payer);
      const sig = await (web3 as any).sendAndConfirmTransaction(conn, tx, [payer], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ txid: sig }, null, 2));
    });

  program.command("init-config")
    .requiredOption("--keypair <PATH>")
    .requiredOption("--mint <MINT>")
    .requiredOption("--agg-key <PATH>")
    .option("--chain-id <U64>")
    .action(async (opts) => {
      const web3 = await import("@solana/web3.js");
      const fs = require("node:fs");
      const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
      if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");
      const conn = new (web3 as any).Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new (web3 as any).PublicKey(programIdStr);
      const zkslMint = new (web3 as any).PublicKey(opts.mint);
      const payer = readKeypair(opts.keypair, web3);

      // Read aggregator secret (hex 64 bytes) and derive pubkey
      const raw = fs.readFileSync(opts["aggKey"], { encoding: "utf8" });
      const obj = JSON.parse(raw);
      const hex = obj.secretKey as string;
      if (!hex || typeof hex !== "string") throw new Error("agg-key secretKey missing");
      const sec = Uint8Array.from(Buffer.from(hex, "hex"));
      const agg = (web3 as any).Keypair.fromSecretKey(sec);
      const aggPub = agg.publicKey.toBytes();
      const activationSeq = BigInt(1);
      const chainId = BigInt(opts.chainId ? String(opts.chainId) : (process.env.CHAIN_ID || "1"));

      const configPda = (web3 as any).PublicKey.findProgramAddressSync([Buffer.from("zksl"), Buffer.from("config")], programId)[0];

      // encode initialize(InitializeArgs)
      const disc = sha256_8("global:initialize");
      const activationLe = u64le(BigInt(activationSeq));
      const chainLe = u64le(BigInt(chainId));
      const data = Buffer.concat([
        disc,
        Buffer.from(aggPub), // aggregator_pubkey
        Buffer.from(aggPub), // next_aggregator_pubkey
        activationLe,        // activation_seq u64 LE
        chainLe,             // chain_id u64 LE
      ]);

      const keys = [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: payer.publicKey, isSigner: false, isWritable: false }, // admin = payer
        { pubkey: zkslMint, isSigner: false, isWritable: false },
        { pubkey: configPda, isSigner: false, isWritable: true },
        { pubkey: (web3 as any).SystemProgram.programId, isSigner: false, isWritable: false },
      ];

      const ix = new (web3 as any).TransactionInstruction({ keys, programId, data });
      const tx = new (web3 as any).Transaction();
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = payer.publicKey;
      tx.sign(payer);
      const sig = await (web3 as any).sendAndConfirmTransaction(conn, tx, [payer], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ txid: sig }, null, 2));
    });

  await program.parseAsync(process.argv);
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});

function readKeypair(path: string, web3: any): any {
  const fs = require("node:fs");
  const raw = fs.readFileSync(path, { encoding: "utf8" });
  const arr = JSON.parse(raw);
  const secret = Uint8Array.from(arr);
  return (web3 as any).Keypair.fromSecretKey(secret);
}

function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}


