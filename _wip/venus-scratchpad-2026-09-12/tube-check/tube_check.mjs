// Live check for the bytes build: tube.lookup_channel through macula-mcp's
// own call() (built dist, linked to the local macula-ts), channel id as
// {"$bytes": base64}. Scratch identity, not the running MCP server's.
import { call } from "/home/rl/work/github.com/macula-io/macula-mcp/dist/macula_ts_client.js";

const REALM = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1";
const REAL = process.env.REAL_B64;
const MISSING = process.env.MISSING_B64;
const TEXT_ID = process.env.TEXT_ID;
const identityPath = process.env.CHECK_IDENTITY;

async function attempt(label, callArgs, bytes) {
  const t0 = Date.now();
  try {
    const res = await call({ procedure: "tube.lookup_channel", callArgs, realm: REALM, timeoutMs: 15000, identityPath, bytes });
    console.log(`${label}: OK in ${Date.now() - t0}ms`);
    return res.payload;
  } catch (e) {
    console.log(`${label}: ERROR in ${Date.now() - t0}ms: ${e?.message ?? e}`);
    return undefined;
  }
}

function summarize(p) {
  if (!p || typeof p !== "object") return JSON.stringify(p);
  const clips = Array.isArray(p.clips) ? p.clips : [];
  return JSON.stringify({
    keys: Object.keys(p).sort(),
    channel_id: p.channel_id,
    name: p.name,
    logo_mcid: p.logo_mcid,
    clip_count: clips.length,
    clip_names: clips.map((c) => c.name),
    first_clip_id: clips[0]?.clip_id,
  }, null, 1);
}

const tagged = await attempt("1 bytes id, tagged output", { channel_id: { $bytes: REAL } }, "tagged");
console.log(summarize(tagged));
const hex = await attempt("2 bytes id, default hex output", { channel_id: { $bytes: REAL } }, undefined);
console.log(summarize(hex));
const passedBack = tagged?.channel_id
  ? await attempt("3 the returned channel_id passed straight back", { channel_id: tagged.channel_id }, "tagged")
  : undefined;
console.log(passedBack ? `  same channel: ${JSON.stringify(passedBack.channel_id) === JSON.stringify(tagged.channel_id) && passedBack.name === tagged.name}` : "  (skipped)");
const asText = await attempt("4 same id as a plain text string", { channel_id: TEXT_ID }, "tagged");
console.log(summarize(asText));
const missing = await attempt("5 nonexistent id as bytes", { channel_id: { $bytes: MISSING } }, "tagged");
console.log(summarize(missing));
const bad = await attempt("6 invalid base64 under $bytes (must fail locally)", { channel_id: { $bytes: "not base64!" } }, "tagged");
console.log(summarize(bad));

console.log("CHECKS",
  JSON.stringify({
    tagged_channel_id_echoed: JSON.stringify(tagged?.channel_id) === JSON.stringify({ $bytes: REAL }),
    tagged_logo_is_bytes: typeof tagged?.logo_mcid === "object" && typeof tagged?.logo_mcid?.$bytes === "string",
    hex_channel_id: hex?.channel_id === "0x" + Buffer.from(REAL, "base64").toString("hex"),
  }));
process.exit(0);
