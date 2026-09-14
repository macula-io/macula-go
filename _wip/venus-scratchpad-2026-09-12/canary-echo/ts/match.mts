// Match rule (Saturnus): "match" ignores text versus bytes and map key order.
// In macula-ts, bytes arrive as "0x"-prefixed hex strings (cabi/wirevalue.go:88-90),
// so text versus bytes is visible and "exact_match" reports it. Map key order is
// NOT visible: the FFI builds a Go map and json.Marshal sorts its keys
// (cabi/wirevalue.go:110-118, cabi/rpc.go:130), so exact_match here cannot
// catch a key-order change.

function decodeHexText(s: string): string {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(s)) return s;
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(s.slice(2), "hex"));
  } catch {
    return s;
  }
}

export function canonical(v: unknown, decodeBytes: boolean): string {
  if (typeof v === "string") return JSON.stringify(decodeBytes ? decodeHexText(v) : v);
  if (Array.isArray(v)) return "[" + v.map((x) => canonical(x, decodeBytes)).join(",") + "]";
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return "{" + Object.keys(o)
      .map((k) => [decodeBytes ? decodeHexText(k) : k, o[k]] as const)
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .map(([k, val]) => JSON.stringify(k) + ":" + canonical(val, decodeBytes))
      .join(",") + "}";
  }
  return JSON.stringify(v);
}

export const contentMatch = (reply: unknown, sent: unknown): boolean => canonical(reply, true) === canonical(sent, true);
export const exactMatch = (reply: unknown, sent: unknown): boolean => canonical(reply, false) === canonical(sent, false);
