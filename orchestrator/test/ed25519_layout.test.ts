import { describe, it, expect } from "vitest";
import * as nacl from "tweetnacl";
import * as web3 from "@solana/web3.js";
import { buildDS } from "../src/crypto.js";

describe("Ed25519 instruction layout (single signature)", () => {
  it("has num=1, in-instruction refs (0xFFFF), and msg_len=110", () => {
    const kp = nacl.sign.keyPair();
    const zero32 = new Uint8Array(32);
    const { ds } = buildDS({ chainId: 1n, programId: zero32, proofHash: zero32, startSlot: 1n, endSlot: 1n, seq: 1n });
    const sig = nacl.sign.detached(ds, kp.secretKey);
    const ix = web3.Ed25519Program.createInstructionWithPublicKey({
      publicKey: kp.publicKey,
      message: Buffer.from(ds),
      signature: Buffer.from(sig),
    });
    const data: Buffer = ix.data as Buffer;
    expect(data.byteLength).toBeGreaterThan(16);
    const num = data.readUInt8(0);
    const sigIx = data.readUInt16LE(4);
    const pkIx = data.readUInt16LE(8);
    const msgLen = data.readUInt16LE(12);
    const msgIx = data.readUInt16LE(14);
    expect(num).toBe(1);
    expect(sigIx).toBe(0xFFFF);
    expect(pkIx).toBe(0xFFFF);
    expect(msgIx).toBe(0xFFFF);
    expect(msgLen).toBe(110);
  });
});


