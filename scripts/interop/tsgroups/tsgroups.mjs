// tsgroups is @macula-io/ts's side of sealed groups across macula 13.2 and
// TypeScript (through macula-go's shared library), for scripts/interop/groups.sh
// with GROUPS_PEER=ts and erlang_groups.escript, through one station and
// macula's own distributor. The TypeScript twin of gogroups.
//
//   node tsgroups.mjs <host:port@node_id hex> <profile> <realm hex> <realm key hex> <work dir> <prefix> <topic> member
//   node tsgroups.mjs ... stranger
//
// Both print "node <hex>" and wait for <work>/grant.<hex>, the org's grant the
// script minted for this node. member subscribes to topic under the group,
// pulling its epoch from the Erlang distributor, writes <work>/ready.go (the
// barrier the Erlang member waits on), waits for <work>/ready.erlang,
// publishes "from go" sealed under the group, and waits for the Erlang
// member's "from erlang" to arrive opened. stranger, a node the distributor's
// removed set names, checks its subscribe is refused not_a_member. Each prints
// its outcome and exits 1 on any other.
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { GroupError, NodeKey, Pool } from "@macula-io/ts";

const [station, profile, realm, realmKey, work, prefix, topic, mode] = process.argv.slice(2);

function seedOf(text) {
  const m = /^(.+):(\d+)@([0-9a-fA-F]{64})$/.exec(text ?? "");
  if (!m) throw new Error(`the station is host:port@<node_id hex>, not ${JSON.stringify(text)}`);
  return { host: m[1].replace(/^\[(.*)\]$/, "$1"), port: Number(m[2]), nodeId: m[3] };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function waited(path) {
  for (let i = 0; i < 900; i++) {
    if (existsSync(path)) return readFileSync(path, "utf8");
    await sleep(200);
  }
  throw new Error(`no ${path}`);
}

// Subscribes under the group, waiting while the distributor's advertisement
// has not reached the DHT yet.
async function subscribed(pool, group, onEvent) {
  for (let i = 0; i < 150; i++) {
    const sub = await pool.subscribeGroup(realm, topic, group, onEvent).catch((e) => e);
    if (!(sub instanceof GroupError && sub.reason === "no_distributor")) return sub;
    await sleep(200);
  }
  return pool.subscribeGroup(realm, topic, group, onEvent).catch((e) => e);
}

async function member(pool, group) {
  const heard = [];
  const sub = await subscribed(pool, group, (e) => heard.push(e));
  if (sub instanceof Error) throw sub;
  console.log("subscribed");
  writeFileSync(join(work, "ready.go"), "");
  await waited(join(work, "ready.erlang"));
  await pool.publishGroup(realm, topic, "from go", group);
  console.log("published");
  for (let i = 0; i < 600; i++) {
    for (const e of heard) {
      if (e.unopened !== undefined) throw new Error(`an event unopened: ${e.unopened}`);
      if (e.payload === "from erlang" && e.sealed === 1) {
        console.log(`opened from erlang under ${e.sealKeyId}`);
        return 0;
      }
    }
    await sleep(100);
  }
  throw new Error("nothing from erlang");
}

async function stranger(pool, group) {
  const refused = await subscribed(pool, group, () => {});
  console.log(`stranger subscribe: ${refused?.message ?? refused}`);
  if (!(refused instanceof GroupError && refused.reason === "not_a_member")) {
    throw new Error("the stranger was not refused not_a_member");
  }
  return 0;
}

const pool = await Pool.connect(await NodeKey.generate(profile), [seedOf(station)],
  { realmTrust: [{ realm, key: realmKey }] });
try {
  const self = pool.nodeId();
  console.log(`node ${self}`);
  const group = { prefix, ucan: (await waited(join(work, `grant.${self}`))).trim() };
  process.exitCode = mode === "member" ? await member(pool, group) : await stranger(pool, group);
} catch (e) {
  console.error(`tsgroups: ${e?.message ?? e}`);
  process.exitCode = 1;
} finally {
  await pool.close();
}
