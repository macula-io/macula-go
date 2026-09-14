// Canary caller for io.macula.echo using @macula-io/ts 0.15.0 (the published npm
// package, installed in this folder): the shape of
// examples/02_call.ts, pointed at the echo service. Prepared for the
// hecate-echo on macula 10.24.0 canary; run only when Saturnus calls the
// baseline. One fresh identity, two calls, no loops. Match rule: see match.mts.
//
// Usage: MACULA_CANARY_RUN=<run id> node call_echo.mts <station-host> [port]
import { Identity, Session } from "@macula-io/ts";
import { contentMatch, exactMatch } from "./match.mts";

const PROCEDURE = "io.macula.echo";
const SDK = "macula-ts";
const SDK_VERSION = "0.15.0";

const host = process.argv[2];
const port = Number(process.argv[3] ?? 4433);
if (!host) {
  console.error("usage: node call_echo.mts <station-host> [port]");
  process.exit(2);
}
const RUN = process.env.MACULA_CANARY_RUN;
if (!RUN) {
  console.error("MACULA_CANARY_RUN (the run id Saturnus names) is required");
  process.exit(2);
}
const station = `${host}:${port}`;

function emit(fields: Record<string, unknown>): void {
  console.log(JSON.stringify({ sdk: SDK, sdk_version: SDK_VERSION, run: RUN, station, ...fields }));
}

let ok = true;
const id = Identity.generate();
let session: Session;
const connectStart = performance.now();
try {
  session = await Session.connect(host, port, id);
} catch (e: any) {
  emit({ utc: new Date().toISOString(), call: "connect", match: false, exact_match: false,
         duration_ms: Math.round(performance.now() - connectStart), error: String(e?.message ?? e) });
  id.dispose();
  process.exit(1);
}

async function callAndRecord(call: string, payload: any): Promise<void> {
  const utc = new Date().toISOString();
  const t0 = performance.now();
  try {
    const reply = await session.call(PROCEDURE, payload, { deadlineMs: 5000 });
    const match = contentMatch(reply, payload);
    emit({ utc, call, match, exact_match: exactMatch(reply, payload),
           duration_ms: Math.round(performance.now() - t0), is_error: false, reply });
    ok = ok && match;
  } catch (e: any) {
    const duration_ms = Math.round(performance.now() - t0);
    if (e?.name === "MaculaCallError") {
      emit({ utc, call, match: false, exact_match: false, duration_ms, is_error: true,
             code: e.code, name: e.bolt4Name, retryable: e.retryable, detail: e.detail });
    } else {
      emit({ utc, call, match: false, exact_match: false, duration_ms, error: String(e?.message ?? e) });
    }
    ok = false;
  }
}

await callAndRecord("hello", "hello");
await callAndRecord("map", {
  sdk: SDK,
  sdk_version: SDK_VERSION,
  run: RUN,
});

await session.close(id);
id.dispose();
process.exit(ok ? 0 : 1);
