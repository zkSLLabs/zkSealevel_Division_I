import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

describe("/anchor chain id mismatch", () => {
  beforeAll(() => {
    process.env.PROGRAM_ID_VALIDATOR_LOCK = "11111111111111111111111111111111";
    process.env.CHAIN_ID = "2"; // env chain id
  });

  it("returns 400 ChainIdMismatch when on-chain config chain_id differs", async () => {
    const vi = (await import("vitest")) as any;
    vi.vi.resetModules();
    // Mock onchain helpers before importing server
    vi.vi.mock("../src/onchain.js", () => ({
      fetchConfig: async () => ({
        aggregator_pubkey: new Uint8Array(32),
        next_aggregator_pubkey: new Uint8Array(32),
        activation_seq: 1n,
        chain_id: 1n, // on-chain chain id different from env C
      }),
      fetchLastSeq: async () => 0n,
    }));
    const mod = await import("../src/server.js");
    const app = (mod as any).app as any;

    // create artifact via /prove
    const prove = await request(app)
      .post("/prove")
      .set("Idempotency-Key", "test-prove-1")
      .send({ start_slot: 1, end_slot: 1, state_root_before: "0".repeat(64), state_root_after: "f".repeat(64) });
    expect(prove.status).toBe(200);
    const artifactId = (prove.body || {}).artifact_id;

    const resp = await request(app)
      .post("/anchor")
      .set("Idempotency-Key", "test-anchor-1")
      .send({ artifact_id: artifactId });
    expect(resp.status).toBe(400);
    expect(resp.body?.error?.code).toBe("ChainIdMismatch");
  });
});


