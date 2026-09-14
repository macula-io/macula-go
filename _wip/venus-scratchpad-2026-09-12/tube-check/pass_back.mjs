// Re-run of step 3 with a value comparison (the first run compared tagged
// objects by reference). Calls once with the known id, then passes the
// returned channel_id object straight back and compares whole payloads.
import { call } from "/home/rl/work/github.com/macula-io/macula-mcp/dist/macula_ts_client.js";
const REALM = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1";
const identityPath = process.env.CHECK_IDENTITY;
const args = (channel_id) => ({ procedure: "tube.lookup_channel", callArgs: { channel_id }, realm: REALM, timeoutMs: 15000, identityPath, bytes: "tagged" });
const first = (await call(args({ $bytes: process.env.REAL_B64 }))).payload;
const second = (await call(args(first.channel_id))).payload;
const text = (v) => (v && typeof v === "object" && typeof v.$bytes === "string" ? Buffer.from(v.$bytes, "base64").toString("utf8") : v);
console.log(JSON.stringify({
  passed_back: first.channel_id,
  whole_payload_identical: JSON.stringify(second) === JSON.stringify(first),
  name_as_utf8: text(first.name),
  description_type: typeof first.description === "object" ? "tagged bytes" : typeof first.description,
  owner_type: typeof first.owner === "object" && first.owner !== null && "$bytes" in first.owner ? "tagged bytes" : typeof first.owner,
  tags: first.tags,
  clip_fields: Object.keys(first.clips?.[0] ?? {}).sort(),
  view_count_type: typeof first.clips?.[0]?.view_count,
}, null, 1));
process.exit(0);
