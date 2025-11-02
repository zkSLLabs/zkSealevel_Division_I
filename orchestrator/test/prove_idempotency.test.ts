import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

describe("/prove idempotency", () => {
  let app: any;
  beforeAll(async () => {
    const mod = await import("../src/server.js");
    app = (mod as any).app as any;
  });

  it("returns identical bodies for the same Idempotency-Key", async () => {
    const key = "prove-idem-1";
    const body = { start_slot: 1, end_slot: 1, state_root_before: "0".repeat(64), state_root_after: "0".repeat(64) };
    const a = await request(app).post("/prove").set("Idempotency-Key", key).send(body);
    const b = await request(app).post("/prove").set("Idempotency-Key", key).send(body);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(JSON.stringify(a.body)).toBe(JSON.stringify(b.body));
  });
});


