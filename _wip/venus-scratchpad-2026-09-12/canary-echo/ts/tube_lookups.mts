// Tube canary lookups using @macula-io/ts 0.15.0 (the published npm package, installed
// in this folder): tube.lookup_channel and tube.lookup_video_clip as plain calls in
// io.macula, ids sent as {"$bytes": base64}, replies read with bytes: "tagged". TS has
// no stream API, so this caller does the lookups only, on one identity. Run only on
// Saturnus's "go" for the tube canary.
//
// Usage: MACULA_CANARY_RUN=<run id> node tube_lookups.mts <station-host> [port]
import { Identity, MaculaCallError, Session } from "@macula-io/ts";
import { contentSha256, textOf } from "./tube_digest.mts";

const SDK = "macula-ts";
const SDK_VERSION = "0.15.0";
const REALM = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1";
const CHANNEL_ID = "channel-01a04717ace27d1fa41aed430d0ec70a";
const CLIP_ID = "clip-01a0471969fd71c2930cc459a797e6ca";

const host = process.argv[2];
const port = Number(process.argv[3] ?? 4433);
if (!host) {
  console.error("usage: node tube_lookups.mts <station-host> [port]");
  process.exit(2);
}
const RUN = process.env.MACULA_CANARY_RUN;
if (!RUN) {
  console.error("MACULA_CANARY_RUN (the run id Saturnus names) is required");
  process.exit(2);
}
const station = `${host}:${port}`;

function emit(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ sdk: SDK, sdk_version: SDK_VERSION, run: RUN, station, utc: new Date().toISOString(), ...fields }));
}

const b64 = (s: string): string => Buffer.from(s, "ascii").toString("base64");

const id = Identity.generate();
emit({ call: "identities", identity_a: Buffer.from(id.nodeId).toString("hex") });
let session: Session;
const connectStart = performance.now();
try {
  session = await Session.connect(host, port, id);
} catch (e: any) {
  emit({ call: "connect", outcome: "error", duration_ms: Math.round(performance.now() - connectStart), error: String(e?.message ?? e) });
  id.dispose();
  process.exit(1);
}

async function lookup(procedure: string, key: string, value: string): Promise<boolean> {
  for (let attempt = 1; attempt <= 2; attempt++) {
    const t0 = performance.now();
    const r: Record<string, unknown> = { call: procedure, attempt };
    let retry = false;
    try {
      const reply: any = await session.call(procedure, { [key]: { $bytes: b64(value) } }, { realm: REALM, deadlineMs: 10000, bytes: "tagged" });
      const { sha256, counts } = contentSha256(reply);
      Object.assign(r, {
        outcome: "ok",
        content_sha256: sha256,
        view_counts: counts,
        summary: { name: textOf(reply?.name), channel_id: textOf(reply?.channel_id), clip_count: Array.isArray(reply?.clips) ? reply.clips.length : undefined },
      });
    } catch (e: any) {
      if (e instanceof MaculaCallError) {
        Object.assign(r, { outcome: "call_error", code: e.code, name: e.bolt4Name, detail: e.detail });
        retry = attempt === 1 && e.detail === "bad_request";
      } else {
        Object.assign(r, { outcome: "error", error: String(e?.message ?? e) });
      }
    }
    r.duration_ms = Math.round(performance.now() - t0);
    if (retry) r.hazard = "hecate-tube#3: bad_request, retrying once";
    emit(r);
    if (!retry) return r.outcome === "ok";
  }
  return false;
}

let ok = await lookup("tube.lookup_channel", "channel_id", CHANNEL_ID);
ok = (await lookup("tube.lookup_video_clip", "clip_id", CLIP_ID)) && ok;
await session.close(id);
id.dispose();
process.exit(ok ? 0 : 1);
