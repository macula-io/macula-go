// Local check of the match rule, no network.
import { contentMatch, exactMatch } from "./match.mts";
const sent = { sdk: "macula-ts", sdk_version: "0.14.2", run: "r1" };
const cases: Array<[string, boolean, boolean, unknown]> = [
  ["identical", true, true, { sdk: "macula-ts", sdk_version: "0.14.2", run: "r1" }],
  ["keys reordered", true, true, { run: "r1", sdk_version: "0.14.2", sdk: "macula-ts" }],
  ["one value as bytes", true, false, { sdk: "0x" + Buffer.from("macula-ts").toString("hex"), sdk_version: "0.14.2", run: "r1" }],
  ["changed value", false, false, { sdk: "macula-ts", sdk_version: "0.14.2", run: "r2" }],
];
let bad = 0;
for (const [name, wantContent, wantExact, reply] of cases) {
  const c = contentMatch(reply, sent), x = exactMatch(reply, sent);
  const pass = c === wantContent && x === wantExact;
  if (!pass) bad++;
  console.log(`  ${pass ? "ok  " : "FAIL"} ${name}: match=${c} exact_match=${x}`);
}
const t = contentMatch("0x" + Buffer.from("hello").toString("hex"), "hello") && !exactMatch("0x68656c6c6f", "hello");
console.log(`  ${t ? "ok  " : "FAIL"} "hello" as bytes: content matches, exact does not`);
if (!t) bad++;
process.exit(bad === 0 ? 0 : 1);
