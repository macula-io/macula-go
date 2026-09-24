# PLAN_MACULA_12_RUNTIME.md

**Status:** In Progress
**Created:** 2026-09-24
**Last Updated:** 2026-09-24

## End goal

> So a Go client, and the TypeScript SDK and macula-mcp on it, can reach the
> macula 12 station fleet and the mcl-* services behind it again.

BUILD. Stage A (the post-quantum pieces, each proven against macula v12.1.0:
LAMPS composite, macula-pqc groups, handshake v4, request proofs, neighbour
signing) is on master. This plan is stage B, the runtime rewire, then C, live
interop.

## Decision (Raf, 2026-09-24)

Rewire the current channel-based runtime onto the macula 12 wire now. The
actor port (`PLAN_ACTOR_ARCHITECTURE_DECISION.md`) stays sequenced after
lazymesh, as that decision says. No backward compatibility: the 10.x path is
deleted, not kept beside the new one.

## Shape

A new package, `stationlink`, is the client link to one macula 12 station, as
macula's `macula_station_link`: dial, handshake, status statements, neighbour
signatures, then calls, pubsub and serving on top. The pool, direct dial and
DHT move onto it chunk by chunk, each chunk compiling and green. The last
chunk deletes the 10.x `connection` package and the old primitives
(`identity.KeyPair`, `frame.Sign`, `transport.Dial` and its trust modes, the
10.x frame builders) in one cut, with the examples and README rewritten.

The wire, as macula v12.1.0 implements it (read from source, 2026-09-24):

- One bidirectional control stream, opened by the client, carries the
  handshake (OPENER, CHALLENGE, CONNECT, HELLO, version 4), STATUS (version 4)
  and every CALL, RESULT, ERROR, PUBLISH, EVENT, SUBSCRIBE, ADVERTISE and
  GOODBYE (version 2). Frames are `<<Len:32/big, CBOR>>`, capped at 64 KiB in
  the handshake and 16 MiB after it.
- STATUS goes out at every issuer reissue (15 min); the connection closes when
  the peer's statement is 5 min past expiry or its binding reaches not_after.
- In pq_hybrid the control frames are neighbour-signed with a per-direction
  seq from 0 after HELLO.
- A CALL is a signed request (caller = identity key id), target = the station
  for `_dht.*` and `_macula.ping`, the provider for an org procedure; the reply
  comes back on the control stream and is verified against the request.
- Liveness: `_macula.ping` every 30 s on the zero realm; two misses close.
- DHT: `_dht.put_record`, `_dht.find_record`, `_dht.find_records`,
  `_dht.find_records_by_type` as station CALLs on the zero realm, carrying
  record wire bytes, each verified locally.

## Chunks

- [x] B1 `stationlink`: dial through `transport.DialTarget`, the v4
  handshake, the session state (station key and binding, connection hash),
  STATUS both ways with its timers, neighbour seq, GOODBYE, a reader loop.
  Tested against an in-process Go station built from `handshake`'s station
  side.
- [x] B2 CALL on the link: signed requests, reply and relay-error
  verification, the liveness probe.
- [x] B3 DHT on the link: record bytes, verification, storage keys.
- [x] B4 PubSub on the link: PUBLISH, SUBSCRIBE, EVENT verification, dedup.
- [x] B5 Serving: ADVERTISE with the org directory and delegation chain
  resolved from the DHT and checked against the pinned realm key, the
  connected station as serving station, renewal at half the advertisement's
  lifetime (at most 5 minutes, never past the chain), inbound CALL admission
  as macula_request_admission judges it (per link until B6 gives the pool
  one), handler_error / temporary_relay_failure / unknown_next_peer, and
  UNADVERTISE with a tombstone. Open procedures only: a gated one is refused
  with ErrGatedUnsupported until the PQ UCAN verifier (macula-go#2).
- [x] B6 Pool and direct dial on `stationlink`, replacing the 10.x `pool`
  package, as macula 12.2.1's `macula_client` (surveyed at 76a0994f):
  every seed pinned by node_id; realm keys pinned per realm and checked as
  keys of the pool's profile; one identity key, statement issuer (run by the
  pool), request admission (a share per link, cap = share x links), event
  dedup and publication seq for all links; a link redialed after
  RespawnDelay with its subscriptions and served procedures replayed;
  Publish signed once and sent on ReplicationFactor links; Call by direct
  dial (trusted advertisements from the DHT, freshest first, the serving
  station dialed from its own station_endpoint, a share of the deadline per
  candidate, the next candidate on a reachability failure, the answering
  candidate remembered); `Providers`; the DHT over the links. A direct link
  that never comes up is not kept. Serve now also puts its advertisement in
  the DHT (and its tombstone at Stop), as advertise_direct does: without it
  no direct-dial caller could find a Go provider. Not ported: station
  discovery (macula#31) and macula's new_peer_budget, whose second
  node_id-keyed half macula does not implement either; MaxDirectLinks bounds
  direct dials. Tested against `internal/teststation`, an in-process routing
  station.
- [x] B7a Delete the 10.x path: `connection`, `dht`, `directdial`, `stream`,
  the pre-12 `content`, the Ed25519 `ucan`, `bolt4`, the 10.x frame builders
  and frame-level Ed25519 signing (`frame.Sign`, `publisher_sig`), Ed25519
  identity (`identity.KeyPair`) and the trust-mode `transport.Dial`. New
  examples (`call`, `serve`, `pubsub`) on the pool, each run against the lab
  station; README rewritten for macula 12, streams and content stated absent.
- [x] B7b Streaming RPC, as macula 12.2.1 does it: each session on its own
  QUIC stream the caller opens (the station opens one to the provider),
  STREAM_OPEN a signed request with its mode, provider frames under
  MACULA-PQ-STREAM-V1 and caller frames under MACULA-PQ-CALLER-STREAM-V1, a
  seq per side chained to the open's request hash; admission as for CALLs
  plus session caps (16 per caller, 1000 per node) and inbox bounds (16 MiB
  per stream, per caller, 256 MiB per node); refusal codes as
  `refuse_open`. Lessons from the retired 10.x leak survey, as requirements:
  every dedicated stream is released on every path, success or failure
  (cancel read and write, not just close); an accepted stream that fails
  before a session exists is refused and released; no goroutine per frame.
- [ ] B7c Content transfer: port `manifest` to macula 12 (SHA-384, 50-byte
  MCID tagged 2, the MCID over name, size, chunk size and count, hash
  algorithm and root); `_content.put_block/get_block/put_manifest/
  get_manifest` CALLs to a station on dedicated streams, up to 4 per link;
  content announcements (type 0x11) and fetch by direct dial. Lesson from
  the leak survey: a manifest from the wire is untrusted input, so its
  counts and sizes are bounded before anything is allocated from them.
- [ ] C(i) live against a macula 12.1 lab station on host00; C(ii) one fleet
  station (amsterdam, canary).

## Measured live

**2026-09-24, C(i) early, B1 against a lab station** (macula-station 0.6.1,
`ghcr.io/macula-io/macula-station@sha256:92aa889a…`, build e07ca30, pq_hybrid,
puzzle enforced, loopback on host00, no peers), with
`scripts/interop/golivelink`:

- identity: a puzzle-solved pq_hybrid key in 1.6 s;
- handshake: HELLO accepted in 48 ms; the station logged the client
  connecting and, after `Close`, disconnecting; the link held 10 s with
  nothing unrouted;
- TLS: group **SecP256r1MLKEM768**, suite **TLS_AES_128_GCM_SHA256**, an
  ML-DSA leaf, no resumption. The suite is the one the removed cipher-suite
  pin would have refused. The group is macula-pqc's second: two macula nodes
  settle on SecP384r1MLKEM1024, but Go's crypto/tls chooses which key shares
  to send whatever CurvePreferences' order, and the station accepts either.

**2026-09-24, B2 against the same lab station:** `_macula.ping` is
answered with the station's own signed relay error `unknown_next_peer` in
20 ms, which macula's link counts as alive; `_dht.find_records_by_type`
{type: node_record} is answered with a verified RESULT, a list of one (the
station's own record), in 17 ms; nothing unrouted.

**2026-09-24, B3 against the same lab station:** find_records_by_type
node_record: 1 verified, 0 dropped, 17 ms; find_record of the station's
station_endpoint key: a verified 0x12 record, 17 ms; put_record of a node
record macula-go signed in pq_hybrid (8,518 bytes, the LAMPS composite):
accepted by the station, which verifies every put, 23 ms; find_record of
its storage key: the same record back, verified.

**2026-09-24, B4 against the same lab station:** SUBSCRIBE, then PUBLISH
of a publication signed in pq_hybrid; the station delivered it back as a
verified EVENT (`delivered_via` direct) in 9 ms; nothing unrouted.

**2026-09-24, B5 against the same lab station** (`golivelink -serve 14m`):
a Go provider served `golivelink/echo` under a throwaway test realm (org
directory and delegation put in the station's DHT), renewing its 5-minute
advertisement every 2.5 minutes on the same connection; a second Go link
called it through the station every 30 s. RESULT in 14 to 25 ms until
t+9m31s, then `unknown_next_peer` from t+10m1s to t+12m1s, RESULT again
from t+12m31s. The station drops a same-connection renewal as a duplicate
and purges the entry 5 minutes past the first advertisement's expiry:
macula-io/macula-station#7.

**2026-09-24, B6 against the same lab station** (`golivelink -serve 90s
-every 15s`): the provider's advertisement, with its authorization, was put
in the station's DHT; a second node's `pool` resolved it, checked it against
the test realm's key, took the station's own endpoint record, dialed it
pinned and called the provider there. First call 34 ms (resolution and
dial), then 16 to 25 ms on the remembered candidate, seven of seven
answered.

**2026-09-24, B7b against the same lab station** (`golivelink -serve`):
`golivelink/watch`, a server stream opened by direct dial from a second
node's pool: first chunk at 53 to 66 ms (resolution, dial, open), then one
every 5 to 7 ms, the end at 73 to 82 ms; `golivelink/count`, a client
stream of three chunks, answered by the provider's reply at 67 ms. The
station verifies each relayed frame against the open, so it read the
provider's and the caller's signed frames; its log shows no refusal.

## @macula-io/ts (macula-ts `cabi`) across B7

macula-ts's `cabi` pins macula-go v0.7.1, so B7a does not break its build;
it breaks when the pin moves past it. Every `cabi` export spoke the 10.x
wire and none reaches a macula 12 station today. **Do not tag macula-go for
TS until `cabi` moves to this API.** Where each export lands:

| `cabi` exports | 10.x packages | macula 12 replacement | Ready |
|---|---|---|---|
| `macula_identity_generate`, `_from_seed_bytes`, `_node_id`, `_private_bytes`, `_free`; `macula_identity_sign` | identity (Ed25519) | `identity.GenerateIdentityKey`, `LoadKey`/`Save`, `NodeKey.NodeID`, `Sign` (key files replace raw private bytes) | B7a |
| `macula_session_connect`, `_remote_addr`, `_station_node_id`, `_close` | connection, transport | `pool.Connect` with pinned seeds and realm trust, `Status`, `Close` | B6 |
| `macula_session_call`, `macula_directdial_resolve`, `_call` | frame, dht, directdial | `pool.Call`, `pool.Providers` | B6 |
| `macula_session_advertise`, `_unadvertise`, `macula_serve_wait_for_call`, `macula_pending_call_*`, `macula_directdial_advertise` | connection, frame | `pool.Serve` with a `Handler`, `Served.Stop` | B6 |
| `macula_session_publish`, `_subscribe_start`, `_subscribe_stop` | frame | `pool.Publish`, `pool.Subscribe`, `Subscription.Unsubscribe` | B6 |
| `macula_dht_find_record`, `_find_records`, `_find_records_by_type` | connection, dht | `pool.FindRecord`, `FindRecords`, `FindRecordsByType` | B6 |
| `macula_dht_put_procedure_advertisement`, `_put_content_announcement` | dht | `pool.PutRecord` (a procedure advertisement comes from `Serve`) | B6 / B7c |
| `macula_content_put`, `_get` | content, manifest | B7c | no |
| `macula_ucan_mint`, `_decode`, `macula_session_call_with_ucan` | ucan (Ed25519) | PQ UCAN, macula-go#2; `pool.Call` carries a token | no |

## Found in macula and macula-station

- A handler's `{error, R}` went out with provider code `unknown_error`, while
  the caller unwraps only `handler_error`: macula-io/macula#28, fixed in
  macula 12.2.1.
- The facade's ADVERTISE sets `serving_station` to the provider's own node_id;
  the design and `macula_direct_dial` use the connected station's:
  macula-io/macula#29, fixed per link in macula 12.3.0 (eb84b5ea). It
  affected only the ADVERTISE a station routes by: the DHT record direct
  dial resolves, from `macula_direct_dial:publish_advertisement` (reached by
  `advertise_direct`, so by mcl_om), has named the connected station all
  along (v12.2.1 `macula_direct_dial.erl:406,431`), so a Go caller can
  direct-dial mcl-* providers. The earlier note here said otherwise; it was
  read from the facade alone.
- macula-io/macula#30 (unary CALL admission) was read against a checkout 103
  commits behind; the admission has been in since macula 12.0.0
  (`on_call_admission/3`). Closed.
- Station discovery calls `hecate_stations.list_stations`, which the fleet no
  longer serves since 2026-09-23: macula-io/macula#31. macula-go's pool has no
  discovery until both SDKs follow `mcl-stations/list_stations`.
- The station drops a same-connection ADVERTISE renewal as a duplicate:
  macula-io/macula-station#7, folded into 0.6.2.

## Success criteria

- [ ] Every chunk green in CI; the cross-stack checks in `scripts/interop`
  still pass.
- [ ] A Go client connects to a live macula 12 station, calls `mcl-echo/echo`,
  publishes and subscribes, and finds records by type; measurements written
  down.
- [ ] No 10.x code left.
