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
- [ ] B6 Pool and direct dial on `stationlink`: seeds with expected node ids,
  realm_trust, reconnect and replay.
- [ ] B7 content and stream onto the link; delete the 10.x path; examples and
  README.
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

## Found in macula while reading it (reported, not fixed here)

- A handler's `{error, R}` goes out with provider code `unknown_error`, while
  the caller unwraps only `handler_error`: macula-io/macula#28.
- The facade's ADVERTISE sets `serving_station` to the provider's own node_id;
  the design and `macula_direct_dial` use the connected station's:
  macula-io/macula#29.
- macula's link runs the request admission for STREAM_OPEN only; a unary
  CALL goes straight to its handler, so a copy runs twice. macula-go admits
  both, as the design says: macula-io/macula#30.

## Success criteria

- [ ] Every chunk green in CI; the cross-stack checks in `scripts/interop`
  still pass.
- [ ] A Go client connects to a live macula 12 station, calls `mcl-echo/echo`,
  publishes and subscribes, and finds records by type; measurements written
  down.
- [ ] No 10.x code left.
