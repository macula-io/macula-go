// Counts a tube watch: channel events by action, clip facts and view facts, content duplicates
// (same payload, any seq) and transport duplicates (same publisher and seq), per-publisher seq
// bases, and the burst window. Reads a mesh_watch result (an array or {events}) or the JSON
// lines record_watch.mts writes, whose recv_utc gives arrival times.
//
// Usage: node analyze_watch.mts <file>
import { readFileSync } from "node:fs";

type Ev = { topic?: string; publisher: string; seq: number; payload: any; recv_utc?: string };

const file = process.argv[2];
if (!file) {
  console.error("usage: node analyze_watch.mts <file>");
  process.exit(2);
}
const raw = readFileSync(file, "utf8").trim();
const whole = (): any => { try { return JSON.parse(raw); } catch { return undefined; } };
const parsed = whole();
const events: Ev[] = parsed !== undefined
  ? (Array.isArray(parsed) ? parsed : parsed.events)
  : raw.split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l)).filter((e) => e.kind !== "status");

const text = (v: any): string | undefined => {
  if (typeof v === "string" && /^0x([0-9a-f]{2})*$/i.test(v)) return Buffer.from(v.slice(2), "hex").toString("utf8");
  if (v && typeof v === "object" && typeof v.$bytes === "string") return Buffer.from(v.$bytes, "base64").toString("utf8");
  return typeof v === "string" ? v : undefined;
};
const canon = (v: any): string =>
  Array.isArray(v) ? `[${v.map(canon).join(",")}]`
  : v && typeof v === "object" ? `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon(v[k])}`).join(",")}}`
  : JSON.stringify(v);
const utc = (ms: number): string => new Date(ms).toISOString();

const kindOf = (e: Ev): string =>
  e.payload?.viewed_at !== undefined ? "view"
  : e.payload?.action !== undefined ? `channel:${text(e.payload.action)}`
  : e.payload?.clip_id !== undefined ? "clip"
  : "other";

const byKind = new Map<string, Ev[]>();
for (const e of events) byKind.set(kindOf(e), [...(byKind.get(kindOf(e)) ?? []), e]);

console.log(`total ${events.length}`);
for (const [kind, evs] of [...byKind.entries()].sort()) {
  const content = new Map<string, number>();
  for (const e of evs) content.set(canon(e.payload), (content.get(canon(e.payload)) ?? 0) + 1);
  const transport = new Map<string, number>();
  for (const e of evs) transport.set(`${e.publisher}/${e.seq}`, (transport.get(`${e.publisher}/${e.seq}`) ?? 0) + 1);
  const copies = [...content.values()];
  const line = [
    `${kind}: ${evs.length}`,
    `unique ${content.size}`,
    `extra copies ${evs.length - content.size}`,
    `max copies ${Math.max(...copies)}`,
    `same-seq repeats ${evs.length - transport.size}`,
  ];
  if (kind === "clip") {
    const clips = new Map<string, number>();
    for (const e of evs) clips.set(text(e.payload.clip_id) ?? "?", (clips.get(text(e.payload.clip_id) ?? "?") ?? 0) + 1);
    line.push(`per clip ${JSON.stringify(Object.fromEntries(clips))}`, `null thumbnails ${evs.filter((e) => e.payload.thumbnail_mcid === null).length}`);
  }
  if (kind === "view") {
    const clips = new Map<string, number>();
    for (const e of evs) clips.set(text(e.payload.clip_id) ?? "?", (clips.get(text(e.payload.clip_id) ?? "?") ?? 0) + 1);
    const times = evs.map((e) => e.payload.viewed_at as number);
    line.push(`per clip ${JSON.stringify(Object.fromEntries(clips))}`, `viewed_at ${utc(Math.min(...times))} .. ${utc(Math.max(...times))}`);
  }
  if (kind.startsWith("channel:")) line.push(`announced_at ${evs.map((e) => utc(e.payload.announced_at).slice(11, 23)).join(" ")}`);
  console.log(line.join(", "));
}

const publishers = new Map<string, Ev[]>();
for (const e of events) publishers.set(e.publisher, [...(publishers.get(e.publisher) ?? []), e]);
for (const [pub, evs] of publishers) {
  const bases = new Map<number, number>();
  for (const e of evs) { const b = Math.floor(e.seq / 1e6); bases.set(b, (bases.get(b) ?? 0) + 1); }
  const seqs = evs.map((e) => e.seq);
  console.log(`publisher ${pub.slice(0, 8)}...: ${evs.length} events, seq ${Math.min(...seqs)} .. ${Math.max(...seqs)}`);
  const epochs = [...new Set(evs.map((e) => Math.round((e.seq - (Math.min(...seqs))) / 1e9) === 0 ? "a" : "b"))];
  void epochs;
  const sorted = [...seqs].sort((a, b) => a - b);
  const starts = [sorted[0], ...sorted.filter((s, i) => i > 0 && s - sorted[i - 1] > 60e6)];
  console.log(`  seq epochs (gap > 60 s): ${starts.map((s) => utc(Math.floor(s / 1000))).join(", ")}`);
}

const ordered = [...events].sort((a, b) => a.seq - b.seq);
const burst = ordered.filter((e) => kindOf(e) !== "channel:heartbeat");
if (burst.length) {
  console.log(`non-heartbeat by seq: first ${kindOf(burst[0])} seq ${burst[0].seq}, last ${kindOf(burst[burst.length - 1])} seq ${burst[burst.length - 1].seq}`);
  const recv = burst.filter((e) => e.recv_utc).map((e) => e.recv_utc as string).sort();
  if (recv.length) console.log(`non-heartbeat arrivals: ${recv[0]} .. ${recv[recv.length - 1]} (${recv.length} with recv_utc)`);
  const stamps = burst.map((e) => e.payload.sent_at ?? e.payload.announced_at).filter((t) => typeof t === "number");
  if (stamps.length) console.log(`sent_at/announced_at in non-heartbeat: ${utc(Math.min(...stamps))} .. ${utc(Math.max(...stamps))}`);
}
const hb = ordered.filter((e) => kindOf(e) === "channel:heartbeat");
if (hb.length) console.log(`heartbeats announced_at: ${hb.map((e) => utc(e.payload.announced_at).slice(11, 23)).join(" ")}`);
