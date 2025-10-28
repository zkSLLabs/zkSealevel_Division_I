/*
  Minimal E2E script per docs:
  - POST /artifact with canonical fields
  - POST /anchor with artifact_id
  - GET /proof/:artifact_id until status is present
*/

async function main() {
  const base = process.env.ORCH_URL || "http://localhost:8080";
  const idem = crypto.randomUUID();
  const artifact = {
    start_slot: 1,
    end_slot: 1,
    state_root_before: "".padEnd(64, "0"),
    state_root_after: "".padEnd(64, "0"),
  };
  const a = await postJson(`${base}/artifact`, artifact, idem);
  if (!a || !(a as any).artifact_id) throw new Error("artifact failed");
  const artifact_id = (a as any).artifact_id as string;
  const anchor = await postJson(`${base}/anchor`, { artifact_id }, crypto.randomUUID());
  // eslint-disable-next-line no-console
  console.log("anchor:", anchor);
  let i = 0;
  while (i++ < 10) {
    const st = await getJson(`${base}/proof/${artifact_id}`);
    // eslint-disable-next-line no-console
    console.log(st);
    await new Promise((r) => setTimeout(r, 2000));
  }
}

async function postJson(url: string, body: unknown, idem?: string): Promise<unknown> {
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (idem) headers["Idempotency-Key"] = idem;
  const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(body) });
  const text = await res.text();
  try { return JSON.parse(text); } catch { return { status: res.status, body: text }; }
}

async function getJson(url: string): Promise<unknown> {
  const res = await fetch(url);
  return await res.json();
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error(e);
  process.exit(1);
});


