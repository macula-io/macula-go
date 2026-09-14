import { contentSha256, textOf } from "./tube_digest.mts";

let failures = 0;
const check = (name: string, pass: boolean): void => {
  console.log(`  ${pass ? "ok  " : "FAIL"} ${name}`);
  if (!pass) failures++;
};
const clip = (name: string, n: number) => ({ name: { $bytes: Buffer.from(name).toString("base64") }, view_count: n });
const channel = { $bytes: Buffer.from("The BEAM Channel").toString("base64") };
const a = contentSha256({ name: channel, clips: [clip("one", 3), clip("two", 7)] });
const b = contentSha256({ clips: [clip("one", 4), clip("two", 9)], name: channel });
const c = contentSha256({ name: { $bytes: Buffer.from("Another Channel").toString("base64") }, clips: [clip("one", 3), clip("two", 7)] });
check("view counts and key order do not change the digest", a.sha256 === b.sha256);
check("a changed name changes the digest", a.sha256 !== c.sha256);
check("view counts are reported in order", a.counts.join() === "3,7" && b.counts.join() === "4,9");
check("textOf decodes a tagged name", textOf(channel) === "The BEAM Channel");
process.exit(failures === 0 ? 0 : 1);
