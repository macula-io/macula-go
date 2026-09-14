// Records every event on io.macula/tube-commons/tube/* in io.macula for a fixed time, one JSON line
// per event with its arrival time (recv_utc), publisher, seq and payload (bytes as "0x" hex, as
// mesh_watch shows them). A subscription is not a tube call. If the connection drops it reconnects
// and resubscribes until the deadline, and logs the gap as a status line. Runs only on Saturnus's
// "watch now". Analyse the output with tube-canary/analyze_watch.mts.
//
// Usage: node record_watch.mts <station-host> <seconds> <out.jsonl>
import { appendFileSync } from "node:fs";
import { Identity, Session } from "@macula-io/ts";

const REALM = "abb81b5a614b63551b400b810648c0c8a78efad845442630c94b46cc95d2fcd1";
const TOPIC = "io.macula/tube-commons/tube/*";

const [host, secondsArg, out] = process.argv.slice(2);
const seconds = Number(secondsArg);
if (!host || !out || !(seconds > 0)) {
  console.error("usage: node record_watch.mts <station-host> <seconds> <out.jsonl>");
  process.exit(2);
}
const deadline = Date.now() + seconds * 1000;
const write = (line: Record<string, unknown>): void => appendFileSync(out, `${JSON.stringify(line)}\n`);
const status = (fields: Record<string, unknown>): void => write({ kind: "status", utc: new Date().toISOString(), ...fields });

const id = Identity.generate();
let session: Session | undefined;
let stop: (() => Promise<void>) | undefined;
let count = 0;

async function finish(code: number): Promise<never> {
  status({ event: "finish", events: count });
  const closing = (async () => {
    await stop?.().catch(() => undefined);
    await session?.close(id).catch(() => undefined);
  })();
  await Promise.race([closing, new Promise((r) => setTimeout(r, 3000))]);
  process.exit(code);
}
setTimeout(() => void finish(0), Math.max(0, deadline - Date.now()));

while (Date.now() < deadline) {
  try {
    status({ event: "connect", host });
    session = await Session.connect(host, 4433, id);
    const closed = new Promise<Error>((resolve) => {
      void session!.subscribe(TOPIC, (evt) => {
        count++;
        write({ recv_utc: new Date().toISOString(), publisher: Buffer.from(evt.publisher).toString("hex"), seq: evt.seq, payload: evt.payload });
      }, { realm: REALM, bytes: "hex", onClosed: resolve }).then((s) => { stop = s; status({ event: "subscribed", topic: TOPIC }); }, resolve);
    });
    const err = await closed;
    status({ event: "closed", error: String(err?.message ?? err) });
    stop = undefined;
    await session.close(id).catch(() => undefined);
    session = undefined;
  } catch (e: any) {
    status({ event: "error", error: String(e?.message ?? e) });
  }
  await new Promise((r) => setTimeout(r, 1000));
}
await finish(0);
