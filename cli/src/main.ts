import dotenv from "dotenv";
dotenv.config({ path: process.cwd() + "/.env" });

import { Command } from "commander";
import { randomUUID, createHash } from "node:crypto";
import * as fs from "node:fs";
import nacl from "tweetnacl";

async function postJson(url: string, body: unknown, idem?: string): Promise<unknown> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (idem) headers["Idempotency-Key"] = idem;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { status: res.status, body: text }; }
}
function sha256_8(s: string): Buffer {
  const h = createHash("sha256").update(s, "utf8").digest();
  return h.subarray(0, 8);
}

async function main() {
  const program = new Command();
  program
    .name("zksl")
    .description("zkSealevel CLI")
    .version("0.1.0");

  // Prove via orchestrator (/prove): minimal inputs
  program.command("prove")
    .requiredOption("--start <U64>")
    .requiredOption("--end <U64>")
    .requiredOption("--srb <HEX32>")
    .requiredOption("--sra <HEX32>")
    .action(async (opts) => {
      const base = process.env.ORCH_URL || "http://localhost:8080";
      const body = {
        start_slot: Number(opts.start),
        end_slot: Number(opts.end),
        state_root_before: String(opts.srb),
        state_root_after: String(opts.sra),
      };
      const resp = await postJson(`${base}/prove`, body, randomUUID());
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(resp, null, 2));
    });

  // Create artifact via orchestrator (/artifact)
  program.command("artifact")
    .requiredOption("--start <U64>")
    .requiredOption("--end <U64>")
    .requiredOption("--srb <HEX32>")
    .requiredOption("--sra <HEX32>")
    .action(async (opts) => {
      const base = process.env.ORCH_URL || "http://localhost:8080";
      const body = {
        start_slot: Number(opts.start),
        end_slot: Number(opts.end),
        state_root_before: String(opts.srb),
        state_root_after: String(opts.sra),
      };
      const resp = await postJson(`${base}/artifact`, body, randomUUID());
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(resp, null, 2));
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
      const conn = new web3.Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new web3.PublicKey(programIdStr);
      const zkslMint = new web3.PublicKey(opts.mint);
      // Detect token program (Token or Token-2022) from mint owner
      const mintAcc = await conn.getAccountInfo(zkslMint);
      if (!mintAcc) throw new Error("Mint account not found");
      const tokenProgramId = new web3.PublicKey(mintAcc.owner);
      const payer = await readKeypair(opts.keypair);

      const [configPda] = await web3.PublicKey.findProgramAddress([Buffer.from("zksl"), Buffer.from("config")], programId);
      const [validatorRecordPda] = await web3.PublicKey.findProgramAddress([Buffer.from("zksl"), Buffer.from("validator"), payer.publicKey.toBytes()], programId);
      const [escrowAuthorityPda] = await web3.PublicKey.findProgramAddress([Buffer.from("zksl"), Buffer.from("escrow"), payer.publicKey.toBytes()], programId);
      const ASSOCIATED_TOKEN_PROGRAM_ID = new web3.PublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");
      const [validatorAta] = await web3.PublicKey.findProgramAddress([
        payer.publicKey.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID);
      const [escrowAta] = await web3.PublicKey.findProgramAddress([
        escrowAuthorityPda.toBytes(),
        tokenProgramId.toBytes(),
        zkslMint.toBytes(),
      ], ASSOCIATED_TOKEN_PROGRAM_ID);

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
      const ix = new web3.TransactionInstruction({ keys, programId, data });
      const computeIx = (web3 as any).ComputeBudgetProgram?.setComputeUnitLimit
        ? web3.ComputeBudgetProgram.setComputeUnitLimit({ units: 200_000 })
        : null;
      const tx = new web3.Transaction();
      if (computeIx) tx.add(computeIx);
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = payer.publicKey;
      tx.sign(payer);
      const sig = await web3.sendAndConfirmTransaction(conn, tx, [payer], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
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
      const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
      if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");
      const conn = new web3.Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new web3.PublicKey(programIdStr);
      const zkslMint = new web3.PublicKey(opts.mint);
      const payer = await readKeypair(opts.keypair);

      // Read aggregator secret (Solana keypair array or hex) and derive pubkey
      const raw = fs.readFileSync(opts["aggKey"], { encoding: "utf8" });
      const parsed = JSON.parse(raw);
      let aggPub: Uint8Array;
      if (Array.isArray(parsed) && parsed.length === 64) {
        const sec = Uint8Array.from(parsed);
        const kp = nacl.sign.keyPair.fromSecretKey(sec);
        aggPub = kp.publicKey;
      } else if (typeof parsed === "object" && parsed.secretKey) {
        const hex = parsed.secretKey;
        if (hex.length !== 128) throw new Error("agg-key secretKey must be 64-byte hex");
        const sec = Uint8Array.from(Buffer.from(hex, "hex"));
        const kp = nacl.sign.keyPair.fromSecretKey(sec);
        aggPub = kp.publicKey;
      } else {
        throw new Error("Invalid aggregator key format");
      }

      const [configPda] = await web3.PublicKey.findProgramAddress([Buffer.from("zksl"), Buffer.from("config")], programId);

      // encode initialize(InitializeArgs)
      const disc = sha256_8("global:initialize");
      const activationLe = u64le(1n);
      const chainLe = u64le(BigInt(opts.chainId ? String(opts.chainId) : (process.env.CHAIN_ID || "103")));
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

      const ix = new web3.TransactionInstruction({ keys, programId, data });
      const tx = new web3.Transaction();
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = payer.publicKey;
      tx.sign(payer);
      const sig = await web3.sendAndConfirmTransaction(conn, tx, [payer], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ txid: sig }, null, 2));
    });

  program.command("update-config")
    .requiredOption("--keypair <PATH>")
    .requiredOption("--agg-key <PATH>")
    .option("--next-agg-key <PATH>")
    .option("--activation <U64>")
    .option("--paused <BOOL>")
    .action(async (opts) => {
      const web3 = await import("@solana/web3.js");
      const programIdStr = process.env.PROGRAM_ID_VALIDATOR_LOCK || "";
      if (!programIdStr) throw new Error("PROGRAM_ID_VALIDATOR_LOCK is required");
      const conn = new web3.Connection(process.env.RPC_URL || "http://localhost:8899", { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
      const programId = new web3.PublicKey(programIdStr);
      const admin = await readKeypair(opts.keypair);

      // Derive aggregator pubkey from agg-key file
      const raw = fs.readFileSync(opts["aggKey"], { encoding: "utf8" });
      const parsed = JSON.parse(raw);
      let aggPub: Uint8Array;
      if (Array.isArray(parsed) && parsed.length === 64) {
        const sec = Uint8Array.from(parsed);
        const kp = nacl.sign.keyPair.fromSecretKey(sec);
        aggPub = kp.publicKey;
      } else if (typeof parsed === "object" && parsed.secretKey) {
        const hex = parsed.secretKey;
        if (hex.length !== 128) throw new Error("agg-key secretKey must be 64-byte hex");
        const sec = Uint8Array.from(Buffer.from(hex, "hex"));
        const kp = nacl.sign.keyPair.fromSecretKey(sec);
        aggPub = kp.publicKey;
      } else {
        throw new Error("Invalid aggregator key format");
      }
      // Optional next aggregator
      let nextAggPub: Uint8Array | undefined;
      if (opts["nextAggKey"]) {
        const rawN = fs.readFileSync(opts["nextAggKey"], { encoding: "utf8" });
        const parsedN = JSON.parse(rawN);
        if (Array.isArray(parsedN) && parsedN.length === 64) {
          const sec = Uint8Array.from(parsedN);
          const kp = nacl.sign.keyPair.fromSecretKey(sec);
          nextAggPub = kp.publicKey;
        } else if (typeof parsedN === "object" && parsedN.secretKey) {
          const hex = parsedN.secretKey;
          if (hex.length !== 128) throw new Error("next-agg-key secretKey must be 64-byte hex");
          const sec = Uint8Array.from(Buffer.from(hex, "hex"));
          const kp = nacl.sign.keyPair.fromSecretKey(sec);
          nextAggPub = kp.publicKey;
        } else {
          throw new Error("Invalid next aggregator key format");
        }
      }

      const [configPda] = await web3.PublicKey.findProgramAddress([Buffer.from("zksl"), Buffer.from("config")], programId);

      const disc = sha256_8("global:update_config");
      const encOptPub = (present: boolean, pk?: Uint8Array): Buffer => {
        return present && pk ? Buffer.concat([Buffer.from([1]), Buffer.from(pk)]) : Buffer.from([0]);
      };
      const encOptU64 = (present: boolean, v?: bigint): Buffer => {
        return present && typeof v === "bigint" ? Buffer.concat([Buffer.from([1]), u64le(v)]) : Buffer.from([0]);
      };
      const encOptBool = (present: boolean, v?: boolean): Buffer => {
        return present && typeof v === "boolean" ? Buffer.from([1, v ? 1 : 0]) : Buffer.from([0]);
      };

      const activation = opts.activation ? BigInt(String(opts.activation)) : undefined;
      const paused = typeof opts.paused === "string" ? (/^(true|1)$/i.test(String(opts.paused))) : undefined;

      const payload = Buffer.concat([
        encOptPub(true, aggPub),              // aggregator_pubkey = Some
        encOptPub(!!nextAggPub, nextAggPub),  // next_aggregator_pubkey
        encOptU64(activation !== undefined, activation),
        encOptBool(paused !== undefined, paused),
      ]);
      const data = Buffer.concat([disc, payload]);

      const keys = [
        { pubkey: admin.publicKey, isSigner: true, isWritable: false },
        { pubkey: configPda, isSigner: false, isWritable: true },
      ];

      const ix = new web3.TransactionInstruction({ keys, programId, data });
      const tx = new web3.Transaction();
      tx.add(ix);
      const bh = await conn.getLatestBlockhash();
      tx.recentBlockhash = bh.blockhash;
      tx.feePayer = admin.publicKey;
      tx.sign(admin);
      const sig = await web3.sendAndConfirmTransaction(conn, tx, [admin], { commitment: process.env.MIN_FINALITY_COMMITMENT || "finalized" });
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

async function readKeypair(path: string) {
  const web3 = await import("@solana/web3.js");
  const raw = fs.readFileSync(path, { encoding: "utf8" });
  const arr = JSON.parse(raw);
  const secret = Uint8Array.from(arr);
  return web3.Keypair.fromSecretKey(secret);
}

function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n);
  return b;
}


