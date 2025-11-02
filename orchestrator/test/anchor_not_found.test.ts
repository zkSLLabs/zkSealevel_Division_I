import { describe, it, expect, beforeAll } from "vitest";
import request from "supertest";

describe("/anchor not found", () => {
  let app: any;
  beforeAll(async () => {
    const mod = await import("../src/server.js");
    app = (mod as any).app as any;
  });

  it("returns 404 when artifact_id is unknown", async () => {
    const resp = await request(app)
      .post("/anchor")
      .set("Idempotency-Key", "nf-1")
      .send({ artifact_id: "00000000-0000-4000-8000-00000000deaddead" });
    expect(resp.status).toBe(404);
    expect(resp.body?.error?.code).toBe("NotFound");
  });
});


