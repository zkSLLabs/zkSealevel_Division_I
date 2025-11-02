import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

describe("/artifact validation and idempotency", () => {
  let app: any;
  beforeAll(async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zksl-artifacts-"));
    process.env.ARTIFACT_DIR = tmp;
    const mod = await import("../src/server.js");
    app = (mod as any).app as any;
  });

  it("rejects non-hex roots and window > 2048", async () => {
    const badHex = await request(app)
      .post("/artifact")
      .set("Idempotency-Key", "bad-hex-1")
      .send({ start_slot: 1, end_slot: 1, state_root_before: "G".repeat(64), state_root_after: "0".repeat(64) });
    expect(badHex.status).toBe(400);

    const badWindow = await request(app)
      .post("/artifact")
      .set("Idempotency-Key", "bad-window-1")
      .send({ start_slot: 1, end_slot: 3000, state_root_before: "0".repeat(64), state_root_after: "0".repeat(64) });
    expect(badWindow.status).toBe(400);
  });

  it("is idempotent on identical Idempotency-Key headers", async () => {
    const body = { start_slot: 1, end_slot: 64, state_root_before: "0".repeat(64), state_root_after: "f".repeat(64) };
    const key = "idem-1";
    const a = await request(app).post("/artifact").set("Idempotency-Key", key).send(body);
    const b = await request(app).post("/artifact").set("Idempotency-Key", key).send(body);
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
    expect(JSON.stringify(a.body)).toBe(JSON.stringify(b.body));
  });
});


