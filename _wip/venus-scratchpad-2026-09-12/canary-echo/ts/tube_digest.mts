// Content digest for tube lookup replies: view_count removed at any depth (each
// stream run records a view, so counts change between runs), keys sorted, bytes in
// their tagged {"$bytes": base64} form.
import { createHash } from "node:crypto";

function strip(v: unknown, counts: number[]): unknown {
  if (Array.isArray(v)) return v.map((item) => strip(item, counts));
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (k === "view_count") {
        if (typeof val === "number") counts.push(val);
        continue;
      }
      out[k] = strip(val, counts);
    }
    return out;
  }
  return v;
}

export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o).sort().map((k) => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

export function contentSha256(v: unknown): { sha256: string; counts: number[] } {
  const counts: number[] = [];
  const stripped = strip(v, counts);
  return { sha256: createHash("sha256").update(canonical(stripped)).digest("hex"), counts };
}

export function textOf(v: unknown): unknown {
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    const o = v as Record<string, unknown>;
    if (Object.keys(o).length === 1 && typeof o.$bytes === "string") return Buffer.from(o.$bytes, "base64").toString("utf8");
  }
  return v;
}
