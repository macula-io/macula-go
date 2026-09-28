// tssealed is @macula-io/ts's side of sealed calls and streams across macula 13
// and TypeScript (E2E seal scheme 1, through macula-go's shared library), for
// scripts/interop/erlang_sealed.escript, through one station. The TypeScript
// twin of gosealed.
//
//   node tssealed.mjs <host:port@node_id hex> <profile> <realm hex> serve <hold s>
//   node tssealed.mjs <host:port@node_id hex> <profile> <realm hex> call <provider node_id hex> [<peer>]
//
// serve connects a pool with kemAdvertise 1, serves ~<self>/vault (a call) and
// ~<self>/watch (a server stream), both confidential "required", refuses any
// request that did not arrive sealed, prints "node <hex>" and "serving" and
// holds. call calls ~<provider>/vault and opens ~<provider>/watch with
// confidential "required", expecting the peer's texts ("kept by <peer>",
// "chunk from <peer>", "streamed by <peer>", peer "erlang" by default), then
// checks that confidential "off" is refused (invalid_argument). It also takes
// the caller's seal report (@macula-io/ts 0.25.0, macula-go v0.19.0) of the call
// and of the stream, and requires each to say sealed 1, the provider called and
// a 16-hex key id. It prints each outcome and exits 1 on any other.
//
// Unlike gosealed, call makes no clear call to an explicit target: @macula-io/ts
// has no API for one. That the provider refuses a clear call sealed_required is
// checked in the other direction, by erlang_sealed.escript's call_station/8
// against serve.
import { MaculaError, NodeKey, Pool, StreamMode } from "@macula-io/ts";

const [station, profile, realm, mode, arg, peer = "erlang"] = process.argv.slice(2);

function seedOf(text) {
  const m = /^(.+):(\d+)@([0-9a-fA-F]{64})$/.exec(text ?? "");
  if (!m) throw new Error(`the station is host:port@<node_id hex>, not ${JSON.stringify(text)}`);
  return { host: m[1].replace(/^\[(.*)\]$/, "$1"), port: Number(m[2]), nodeId: m[3] };
}

const own = (node, name) => `~${node}/${name}`;
const text = (hex) => Buffer.from(String(hex).replace(/^0x/, ""), "hex").toString("utf8");

async function serve(pool, hold) {
  const self = pool.nodeId();
  await pool.serve(realm, own(self, "vault"), (r) => {
    if (r.sealed !== 1) throw new Error("a clear request reached the handler");
    return "kept by ts";
  }, { confidential: "required" });
  await pool.serveStream(realm, own(self, "watch"), StreamMode.Server, async (s, r) => {
    if (r.sealed !== 1) throw new Error("a clear session reached the handler");
    await s.send(new TextEncoder().encode("chunk from ts"));
    await s.reply("streamed by ts");
  }, { confidential: "required" });
  console.log("serving");
  await new Promise((resolve) => setTimeout(resolve, Number(hold) * 1000));
  return 0;
}

async function call(pool, provider) {
  const vault = own(provider, "vault");
  const watch = own(provider, "watch");
  let reported;
  for (let i = 0; i < 150; i++) {
    reported = await pool.callReport(realm, vault, { n: 1 }, { confidential: "required", timeoutMs: 10_000 }).catch((e) => e);
    if (!(reported instanceof MaculaError && reported.kind === "no_provider")) break;
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  const called = reported instanceof Error ? reported : reported.result;
  console.log(`sealed call: ${called instanceof Error ? `${called.name} ${called.message}` : JSON.stringify(called)}`);
  let ok = called === `kept by ${peer}`;
  const callReport = reported instanceof Error ? null : reported.report;
  console.log(`call report: ${JSON.stringify(callReport)}`);
  ok = ok && sealedTo(callReport, provider);

  const stream = await pool.openStream(realm, watch, StreamMode.Server, {}, { confidential: "required", timeoutMs: 10_000 });
  let chunk = null;
  let reply = null;
  let streamReport = null;
  try {
    for (let i = 0; i < 4 && reply === null; i++) {
      const event = await stream.recv({ timeoutMs: 10_000 });
      if (event.kind === "data") chunk = text(event.body);
      if (event.kind === "reply") reply = event.payload;
      if (event.kind === "end" && event.role === "both") break;
    }
    // Settled on the provider's first chunk opened under the stream's key, and
    // kept after the end.
    streamReport = stream.report();
  } catch (e) {
    console.log(`sealed stream error: ${e instanceof Error ? `${e.name} ${e.message}` : e}`);
  } finally {
    await stream.free();
  }
  console.log(`sealed stream: chunk ${JSON.stringify(chunk)}, reply ${JSON.stringify(reply)}`);
  console.log(`stream report: ${JSON.stringify(streamReport)}`);
  ok = ok && chunk === `chunk from ${peer}` && reply === `streamed by ${peer}` && sealedTo(streamReport, provider);

  // Off is refused, never ignored: a clear call is an explicit target's, and
  // @macula-io/ts offers none.
  const off = await pool.call(realm, vault, { n: 1 }, { confidential: "off", timeoutMs: 10_000 }).catch((e) => e);
  console.log(`off: ${off instanceof MaculaError ? `refused ${off.kind}` : JSON.stringify(off)}`);
  ok = ok && off instanceof MaculaError && off.kind === "invalid_argument";
  return ok ? 0 : 1;
}

// A report that says the exchange was sealed to that provider, under a key.
function sealedTo(report, provider) {
  return report !== null && report.sealed === 1 && report.provider === provider && /^[0-9a-f]{16}$/.test(report.sealKeyId ?? "");
}

const seed = seedOf(station);
const pool = await Pool.connect(await NodeKey.generate(profile), [seed],
  { realmTrust: [], kemAdvertise: mode === "serve" ? 1 : 0, timeoutMs: 60_000 });
console.log(`node ${pool.nodeId()}`);
let status = 1;
try {
  if (mode === "serve") status = await serve(pool, arg);
  else if (mode === "call") status = await call(pool, arg);
  else console.error(`tssealed: mode ${JSON.stringify(mode)} is serve or call`);
} catch (e) {
  console.error(`tssealed: ${e instanceof Error ? e.message : e}`);
} finally {
  await pool.close();
}
process.exit(status);
