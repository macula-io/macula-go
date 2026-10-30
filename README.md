# macula-go

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-go/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-go/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Go Reference](https://img.shields.io/badge/go-1.27%2B-00ADD8?logo=go)](https://go.dev)
[![memory safety](https://img.shields.io/badge/memory%20safety-no%20unsafe%20or%20cgo-success.svg)](https://pkg.go.dev/unsafe)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)
[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-support-ffdd00.svg?logo=buymeacoffee&logoColor=black)](https://buymeacoffee.com/rlefever)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-go-full-dark.svg">
    <img src="assets/macula-go-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Go port of the Macula SDK, on wire 1.0 (macula 15): TLS 1.3 with a hybrid post-quantum key exchange, and ML-DSA-87 signatures</strong>
</p>

---

> **Status, 2026-10-20:** v0.28.0 speaks **wire 1.0** (macula 15) and nothing
> older, and admits a realm member on an endorsement of at most 24 hours: a station before wire 1.0 does not accept it. The fleet moves to wire
> 1.0 on 20 Oct 2026 at 16:00 UTC; until then v0.26.0 is the release for the
> 14.x fleet, and from then on it can no longer connect. Handshake, calls,
> streaming RPC, publish/subscribe, the DHT, serving procedures (under an org
> or in a node's own namespace) and node-served content work as before, now on
> the wire 1.0 envelope, handshake and records, held to macula's wire 1.0
> conformance vectors in every `go test`. Calls and streams are sealed end to end (scheme
> 1), checked both ways against macula 15.6.0 from hex.pm in `pq_pure`
> and `pq_hybrid`.

## What is this?

A Go implementation of a Macula **node**: anything that joins the mesh
without being a station itself. It speaks the same protocol as
[`macula-io/macula`](https://github.com/macula-io/macula), the Erlang/OTP
reference SDK, version 12. Macula is a federated mesh for sovereign
application networks: a **station** routes and holds the DHT, a **realm**
admits orgs, and an org's providers serve procedures that any node in the
realm can call. Any node can also serve procedures in its own namespace,
`~<node_id>/<name>`, with no org or realm to vouch for it.

On the wire:

- **Transport:** QUIC with the ALPN `macula`, TLS 1.3 with a hybrid
  post-quantum key exchange on SecP384r1MLKEM1024 alone, the one hybrid
  group that meets both CNSA 2.0 and BSI TR-02102. Every macula 12 station
  accepts it.
- **Identity:** an ML-DSA-87 key (`pq_pure`) or the composite ML-DSA-87 +
  RSA-PSS-4096 (`pq_hybrid`, the fleet's profile; LAMPS
  `id-MLDSA87-RSA4096-PSS-SHA512`), whose node_id solves the admission
  puzzle.
- **Wire 1.0:** macula-go speaks wire 1.0 (macula `docs/design/WIRE_1_0.md`,
  `frame.WireVersion`, and `macula_wire_version()` in the C library), and runs
  macula's wire 1.0 conformance vectors in every `go test`. A station before
  wire 1.0 does not accept it.
- **Frames:** requests, replies, publications and records are signed
  objects. The connection is authenticated once, by hybrid proofs bound to its
  TLS session (handshake version 5, proof V3), and no control frame carries a
  signature of its own. An unknown frame type, extension or enum value never
  costs a link.

## Features

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Handshake, wire 1.0 (OPENER, CHALLENGE, CONNECT, HELLO, STATUS) | ✅ | — | `stationlink.Dial`, the station pinned by node_id: version 5 alone, negotiated ranges, bound to the TLS exporter; a downgrade or a version below this process's floor for the station is refused; `HandshakeCounters`. Held to macula's wire 1.0 transcripts |
| Deterministic CBOR codec and decoding rule | ✅ | ✅ | Hand-rolled, see [Codec](#the-cbor-codec-is-hand-rolled-on-purpose) |
| Unary RPC (signed CALL, RESULT, ERROR) | ✅ | ✅ | `pool.Call` by direct dial; `pool.Serve` answers with `handler_error`, `temporary_relay_failure` or `unknown_next_peer` |
| Request admission | — | ✅ | Deadline window, each request run once, a copy answered from the stored reply, bounded as macula bounds it |
| Provider authorization | ✅ | ✅ | The realm's org directory and the org's delegation, checked against the realm key the pool pins |
| A node's own namespace (`~<node_id>/<name>`) | ✅ | ✅ | No authorization and no realm key: the advertisement's signature by that node authorizes it; checked against macula's shared fixtures |
| PubSub (signed PUBLISH, SUBSCRIBE, EVENT) | ✅ | ✅ | Published once over several links, delivered once; a subscription that may have missed events says so in-band, see [When a subscription may have missed events](#when-a-subscription-may-have-missed-events) |
| DHT (`_dht.*`) | ✅ | — | Records verified before they are handed on |
| Pool of station links | ✅ | ✅ | Pinned seeds, redial with subscriptions and procedures replayed |
| Streaming RPC (server, client and bidi streams) | ✅ | ✅ | A QUIC stream per session; `pool.OpenStream` by direct dial, `Offer.Stream` to serve; admission, session and inbox bounds as macula's; every stream released on every path |
| Content manifests and MCIDs | ✅ | ✅ | SHA-384, 50-byte MCIDs, byte for byte with macula's `macula_manifest` |
| Node-served content (D27) | ✅ | ✅ | `pool.ShareContent` serves on `~<node_id>/content_v1` and announces; `pool.GetContent` checks the block, the manifest and every chunk against their content ids, bounded, with no realm key; cross-checked both ways against macula 12.6.0 |
| Gated procedures (UCAN) | ✅ | ✅ | `ucan.Create` mints macula 12's post-quantum UCAN (refusing an `exp` more than ten years out, at minting and, as macula does, at verification), `Call.Token` and `Proofs` present it and its chain, `Offer.Policy` gates a procedure as macula's link does (`unauthorized`, or `malformed_frame` for a proof no token names); held to macula's UCAN vectors and checked against `macula_ucan` both ways |
| End-to-end sealing (macula 13, scheme 1) | ✅ | ✅ | A call's or a stream's payloads sealed to the KEM key the provider's advertisement names, so a station routes what it cannot read; see [Sealing](#sealing) |
| Sealed groups (macula 13.2) | ✅ | — | `pool.PublishGroup` and `SubscribeGroup`: a group's events sealed under its current epoch, the epoch pulled from the org's distributor over a sealed call; checked both ways against macula; see [Sealed groups](#sealed-groups) |

No cgo outside `cabi`, which is a C ABI and so cgo by nature, and no
`unsafe` outside `cabi` and identity's Windows key-file guard, which reads a
Win32 security descriptor: `grep -rl '"unsafe"' --include='*.go'` and a
search for `import "C"` name only those files.

## Quick start

```bash
go get github.com/macula-io/macula-go@master
```

A node needs three things to join: a station to link to, **pinned by its
node_id**; the realm id; and the realm's key, which the realm publishes. The
node's own identity key is created on first use and kept in a file readable by
its owner only.

```go
key, err := identity.GenerateIdentityKey(profile.PQHybrid, identity.PuzzleDifficulty)
if err != nil {
	log.Fatal(err)
}
p, err := pool.Connect(ctx, []pool.Seed{{Host: "2a01:4f8::1", Port: 4433, NodeID: stationID}},
	pool.Opts{IdentityKey: key, RealmTrust: map[[32]byte][]byte{realm: realmKey}})
if err != nil {
	log.Fatal(err)
}
defer p.Close()

// Call a procedure: its advertisements are resolved from the DHT, trusted only
// when the realm key authorizes them, and the provider is called at the station
// it serves from. The next candidate is tried only when a station cannot be
// reached; once the CALL has gone out its outcome is returned, a timeout
// included, so a handler is entered at most once per call.
result, err := p.Call(ctx, pool.Call{Realm: realm, Procedure: "mcl-echo/echo", Payload: cbor.Text("hello")})

// Serve one: the realm must have admitted the org, and the org delegated its
// procedures to this node.
served, err := p.Serve(ctx, pool.Offer{Realm: realm, Procedure: "acme/echo",
	Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }})

// Or serve one in this node's own namespace: no org, no realm key.
ring, err := p.Serve(ctx, pool.Offer{Realm: realm, Procedure: record.OwnProcedure(p.NodeID(), "ring"),
	Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }})

// Stream: a server stream's chunks arrive as events until its end.
stream, err := p.OpenStream(ctx, pool.StreamCall{Realm: realm, Procedure: "mcl-tube/watch", Mode: frame.ServerStream})
for {
	event, err := stream.Recv(ctx)
	if err != nil || event.Kind == stationlink.StreamEnd {
		break
	}
	// event.Body is the chunk
}

// Publish and subscribe.
sub, err := p.Subscribe(realm, "acme/demo/greeting_sent_v1")
err = p.Publish(stationlink.Publication{Realm: realm, Topic: "acme/demo/greeting_sent_v1", Payload: cbor.Text("hi")})
for d := range sub.Events() {
	switch d.Kind {
	case pool.KindEvent:
		// d.Event is the event
	case pool.KindGap:
		// events between d.FromMs and d.ToMs may have been missed: resync
	}
}
```

Runnable examples, all with the same flags (`-seed host:port -station <node_id
hex> -realm <hex> -realm-key <file> -key <node key file>`):

| Example | What it does |
|---|---|
| [`examples/call`](examples/call) | Lists a procedure's providers and calls it |
| [`examples/serve`](examples/serve) | Serves an org procedure until interrupted |
| [`examples/pubsub`](examples/pubsub) | Subscribes, publishes one message, prints what it hears |

## Packages

| Package | What it is |
|---|---|
| [`pool`](pool) | A node's station links: seeds, redial and replay, calls by direct dial, serving, pubsub, the DHT |
| [`stationlink`](stationlink) | One link to one station: handshake, STATUS, liveness, calls, serving, pubsub, the DHT |
| [`identity`](identity) | Keys, bindings, status statements, signed objects, key files |
| [`handshake`](handshake) | The v5 and v4 handshake frames, both sides |
| [`frame`](frame) | Signed requests, replies, publications, stream frames, neighbour-signed control frames |
| [`record`](record) | DHT records: sign, verify, storage keys, provider authorization |
| [`transport`](transport) | The post-quantum QUIC dial |
| [`cbor`](cbor) | The deterministic CBOR codec and its decoding rule |
| [`profile`](profile) | The `pq_pure` and `pq_hybrid` crypto profiles |
| [`manifest`](manifest) | Content manifests and MCIDs, as macula 12 makes them |
| [`cabi`](cabi) | The C ABI every non-Go binding uses (.NET, Python, PHP, TypeScript): `macula.h`, its [contract](cabi/CONTRACT.md), and libmacula on each release |
| [`teststation`](teststation) | In-process wire 1.0 stations for tests; `teststation/cmd/teststation` serves them to a binding's tests |
| [`ucan`](ucan) | macula 12's UCAN: mint, verify a chain against a policy, proof ids and did:keys, held to macula's vectors |
| [`devicerequest`](devicerequest) | A device's request to a realm, signed: realm proof v2 (macula-realm#29) |
| [`ownershipproof`](ownershipproof) | The `asserted_by` block of a payload, signed and verified: ownership proof v2 (mcl-om#7) |
| [`seal`](seal) | End-to-end payload sealing, scheme 1: the key agreement, keys, AAD and AES-256-GCM, and a provider's keyring, held to macula 13's vectors |
| [`group`](group) | Sealed groups, the member side: epochs, a group event's seal, the `group_keys_v1` payloads, and the keyring a node holds its groups in, held to macula 13.2's vectors |

## Sealing

macula 13 seals a call's and a stream's payloads end to end (scheme 1:
ML-KEM-1024, with P-384 in `pq_hybrid`, HKDF-SHA-384 and AES-256-GCM), so the
stations that route them see only ciphertext. macula-go seals and opens them
as macula 13.0.0 does, held to its `e2e_seal_v1` vectors and checked both
ways against it (`scripts/interop/sealed.sh`).

A provider names its key by switching `pool.Opts.KEMAdvertise` on. The pool
then holds a KEM keyring (a new key every 24 hours, a replaced key kept 30
minutes, in memory only) and names its current key in the advertisement of
each procedure it serves with `Offer.Confidential`:

| `Offer.Confidential` | Its advertisement | A clear request |
|---|---|---|
| `ConfidentialPreferred` (the default) | names the key | taken while an older keyless advertisement could still be served, then refused `sealed_required` |
| `ConfidentialRequired` (needs `KEMAdvertise`) | names the key | refused `sealed_required` |
| `ConfidentialOff` | names no key | taken |

A caller seals to the key a provider's verified advertisement names, and
never falls back to the clear:

| `Call.Confidential`, `StreamCall.Confidential` | Keyed provider | Keyless provider |
|---|---|---|
| `ConfidentialPreferred` (the default) | sealed | clear |
| `ConfidentialRequired` | sealed | refused, `no_kem_key` |
| `ConfidentialOff` | refused, `pool.ErrConfidentialOff` | refused, `pool.ErrConfidentialOff` |

As in macula's design (§8.1), only an advertisement naming no key is called
in the clear from a pool. A clear call to a keyed provider is an explicit
target's decision: a `stationlink.Call` or `StreamCall` with `Clear`. A call
or an open to a provider states `SealTo` or `Clear`, never both, and one that
states neither is refused `no_signed_state` before anything is sent, as
macula's `call_seal/5` refuses it.

Every answer a provider gives once it has opened a sealed request is sealed,
its refusals included, so a station cannot read which code it answered: only
the sealed length shows, as in macula. Only the refusals that come before
the open (admission, `sealed_refused`, `sealed_required`) are clear. A caller of a
sealed call takes a sealed answer only under the key id it sealed to, and from
the clear only a relay's error, the closed set of refusals macula names before
a request is opened, and `sealed_refused`; it takes anything else as
`stationlink.ErrClearAnswerToSealed`. After `sealed_refused` the pool looks
the provider up once more and reseals, once, as macula does: to the key the
refusal named if any of the provider's advertisements names it (else
`key_mismatch`, or `no_kem_key` when none names a key), or, when the provider
said it holds none, to the first key its advertisements name. A stream
reseals the same way, once, while it has sent nothing, keeping its deadline.
A call that could not be kept confidential ends there: the pool never moves
it to another candidate, which might be keyless. A reseal whose lookup fails
is `no_kem_key`. Once a CALL has gone out, sealed or not, no other candidate
is called at all.

## Sealed groups

macula 13.2 seals a group's events end to end
(`docs/design/DESIGN_E2E_SEALED_PUBSUB.md`): a group is a topic prefix whose
second segment is its org, its events are sealed under the group's current
epoch key, and the org's distributor (`<org>/group_keys_v1`, macula's
`macula_group_keys`) hands the epoch keys to members over a sealed call. A
member presents the org's grant, a UCAN with `can` `group_keys`, and the
distributor decides from its verified identity. macula-go is a member: it
pulls, publishes and subscribes; it runs no distributor.

```go
g := pool.Group{Prefix: "io.macula/acme/chat", UCAN: orgGrant}
sub, err := p.SubscribeGroup(ctx, realm, "io.macula/acme/chat/said_v1", g)
err = p.PublishGroup(ctx, stationlink.Publication{Realm: realm,
	Topic: "io.macula/acme/chat/said_v1", Payload: cbor.Text("hello")}, g)
```

A delivered event names its epoch (`Event.Sealed.KeyID`); one that cannot be
opened arrives once with `Event.Unopened` set to one of macula's closed set
(`not_a_member`, `membership_unknown`, `unknown_epoch`, `epoch_expired`,
`no_distributor`, `no_group`, `tag_invalid`) and a null payload. Every held
group is pulled again at a random instant in its epoch's last third, event or
no event, and a failed pull is retried with backoff until one succeeds. A
publish whose epochs have all stopped publishing pulls at once and fails
closed with that pull's error. A clear `Publish` under a held prefix is
refused (`*pool.GroupHeldError`), and under a `required` group a clear event
is not delivered (`Subscription.RefusedClear`). Under any other group a clear
event under the prefix is delivered with `Event.Sealed` nil; any realm member
can publish one, so check `Sealed` before taking an event as the group's. Epoch keys are held in memory
only and erased once no event under them can be accepted. A plain
`Subscribe` gets a group's events unopened, as `no_group`. Held to macula's
`e2e_seal_v1_group_keys` vectors (the pull's payloads byte for byte, the org
grants' verdicts) and checked both ways against macula 15.6.0
(`scripts/interop/groups.sh`).

`KEMAdvertise` is off by default. Switch it on only once every station runs
macula 12.11 or later, which stores and routes a keyed advertisement, and
every caller runs macula 13 or macula-go 0.18 (the station floor). The fleet's
stations meet it (macula-station 0.12.2, on macula ~> 15.6).

Through the C ABI (still ABI 1): the pool option `kem_advertise`, and
`macula_pool_call_opts`, `macula_pool_open_stream_opts`,
`macula_pool_serve_opts` and `macula_pool_serve_stream_opts`, whose
options JSON carries `confidential`; see the
[contract](cabi/CONTRACT.md#confidentiality).

**Knowing a call was sealed (v0.19.0).** A `preferred` call seals whenever
the provider names a key and goes clear when it names none. To learn which it
was, `pool.CallReport` returns the result with a `stationlink.Report`:
`Sealed` 1 with the `SealKeyID` of the key the request was sealed to, which is
the key its answer opened under, or 0 and no key for a clear call, and the
`Provider` it was addressed to. After a reseal it names the reseal's key. An
error comes with no report. A stream's `Report()` settles on the provider's
first data or reply opened under the stream's key (on a clear stream, its
first data, reply or end) and is `ErrNotSettled` before that; a served stream
has none (`ErrNotACaller`). Through the ABI: `"report": 1` in
`macula_pool_call_opts`, and `macula_stream_report`. It states that sealing ran
on that exchange, nothing more: see macula's
[design](https://github.com/macula-io/macula/blob/main/docs/design/DESIGN_E2E_SEAL_REPORT.md).

Not sealed: publications (macula 13 does not seal them yet, and a sealed
EVENT is counted and not delivered, as macula 13 does), the DHT, and
node-served content, which stays in the clear by design.

## When a subscription may have missed events

A subscription is carried by every station link the pool holds. When the last
of them ends (the station stopped answering liveness probes, closed the
connection, said goodbye), whatever the station sent on that link meanwhile is
gone, and the pool redials and subscribes again. Nothing replays what was
missed, so the subscription says so, on the same `Events()` channel as its
events, where a reader cannot overlook it:

- **`KindInterrupted`**, once, when the last link carrying the subscription
  ends: `FromMs` is when that link last heard anything from its station, and
  `Reason` why it ended (`liveness_lost`, `closed_by_station`, `goodbye`,
  `idle_timeout`, ...; `stationlink.EndReason` has the full set, named as in
  every macula SDK).
- **`KindGap`**, once, when a station accepts the subscription again, before
  any event of the link that now carries it: events published between `FromMs`
  and `ToMs` may have been missed.

Answer a Gap by resyncing what the subscription feeds (for a shared document,
exchange state with its peers). The two times are this node's clock and an
event's `PublishedAt` its publisher's, so they are hints: never drop events by
comparing the two.

Nothing is said when nothing can have been missed: while another link still
carries the subscription (it heard every event, and the pool delivers each
once), for an outage a link survives (QUIC delivers what was held up), at the
first subscribe, and after `Unsubscribe` or `Close`. A station that refuses the
subscription on the new link leaves it interrupted, with no Gap, until one
accepts it; the refusal is counted in the link's `RegisterRefusals`. The
newest notice always gets in: a full subscription makes room by giving up its
oldest delivery, an event (counted in `Dropped`) or, for a reader so far
behind, the Interrupted the Gap then stands for, since the Gap's `FromMs` is
the Interrupted's.

A sealed group subscription (`SubscribeGroup`) delivers its notices in their
place among its events: an Interrupted waits behind events still being opened
(an event may wait for its epoch from the distributor), and does not overtake
them.

Not covered, so that silence is not read as "nothing missed": events a station
refused to write to a link that stayed up, a subscription a station drops when
a membership token ends while the link stays up, and events that never reached
the station.

## The CBOR codec is hand-rolled on purpose

This protocol's deterministic CBOR **deliberately diverges** from RFC 8949's
own canonical-form guidance in two ways: floats always encode as binary64
(never the shortest width that round-trips), and map keys sort by the bytewise
order of their own *encoded* bytes, not their unencoded representation. A
generic "canonical CBOR" library that follows the RFC produces bytes whose
signatures don't verify against a real station. `cbor/` has zero external
dependencies as a result, and its decoding rule is checked against macula's
own vectors (`cbor/testdata/decoding_rule_v1.json`).

## Testing

```bash
go test ./...
```

CI also holds every function to the structural floor
([macula-codebase-checks#9](https://github.com/macula-io/macula-codebase-checks/issues/9)):
deep nesting and tangled functions fail the build. The thresholds are in
[`.golangci.yml`](.golangci.yml); a failure is fixed by splitting the function,
never by a baseline or an inline disable.

The suite needs no network. The pool is tested against
[`teststation`](teststation), an in-process macula 12
station that routes calls between connections, delivers events and holds a
DHT. It is public, so the SDKs built on macula-go (such as @macula-io/ts)
test against the same station.

Checks against a compiled macula, in both directions (key bindings, the LAMPS
composite, the live handshake), and against a live station
(`golivelink`), live in [`scripts/interop/`](scripts/interop) (see its README).
They need macula built with its NIFs and OTP 28, or a running station, so they
are not part of `go test ./...` or CI.

A binary built with `GOFIPS140=v1.0.0` has no ML-DSA (see Known limitations). CI
runs the tests that check such a build says so, and requires a PASS line from
each. They run locally the same way:

```bash
GOFIPS140=v1.0.0 go test ./identity ./handshake ./transport ./frame ./record -run SaysWhetherTheBinaryHasMLDSA -v
```

## Known limitations

- **Content is shared in a node's own namespace only**, `~<node_id>/content_v1`;
  the org form (`<org>/content_v1_<node_id>`) is fetched from but not served.
  Serving needs stations that admit a node's own namespace (macula-station
  0.6.4 and later).
- **Direct dial finds a provider only through the DHT.** A provider is
  reachable from `pool.Call` when it puts its advertisement there, as
  macula's `advertise_direct` (and so every mcl-* service, through mcl_om)
  and Go's `Serve` do. A macula provider that only sends ADVERTISE to its
  station is routed by that station, not found by direct dial.
- **No station discovery beyond the seeds.** macula's discovery calls a
  directory the fleet no longer serves
  ([macula#31](https://github.com/macula-io/macula/issues/31)); both SDKs
  will follow `mcl-stations` together.
- **Not in a `GOFIPS140=v1.0.0` build.** The FIPS 140-3 Go Cryptographic Module
  v1.0.0 has no ML-DSA, and every macula 12 profile signs with ML-DSA-87. In a
  binary built with `GOFIPS140=v1.0.0` (at Go 1.27, `GOFIPS140=certified` names
  the same module), key generation and loading, every verifier and the dial
  return `identity.ErrPostQuantumUnavailable`. Build without `GOFIPS140`, or
  with `GOFIPS140=v1.26.0` or later.

## Status

Measured against a live macula-station 0.6.1 (`pq_hybrid`, puzzle enforced),
2026-09-24, with [`scripts/interop/golivelink`](scripts/interop/golivelink):

- handshake accepted in 14 to 48 ms, on SecP256r1MLKEM768 with an ML-DSA leaf
  (since 0.23.0 every dial settles on SecP384r1MLKEM1024: all six fleet
  stations did, 2026-10-05);
- `_dht.*` finds and puts, each record verified, 17 to 25 ms;
- a publication delivered back as a verified event in 9 ms;
- a server stream opened by direct dial from a second node's pool: first chunk
  at 53 to 66 ms, the next every 5 to 7 ms; a client stream's three chunks
  answered by the provider's reply at 67 ms, the caller's signed frames
  accepted by the station;
- a Go provider served under a test realm and called by a second node's pool
  by direct dial: 34 ms for the first call, 16 to 25 ms after.

On the fleet, 2026-09-24, against amsterdam (station-nl-ams.macula.io): HELLO
in 52 ms, DHT reads and a put, a publication heard back in 86 ms, and
`mcl-echo/echo`, served from another station, called by direct dial and
answered in 348 ms.

## Related projects

| Project | Description |
|---|---|
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) |
| [macula-rust](https://github.com/macula-io/macula-rust) | The Rust port; also ships mobile bindings (Kotlin/Swift via UniFFI) |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, routing, peering |
| [macula-realm](https://github.com/macula-io/macula-realm) | Realm identity: org admission and delegation |

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<http://www.apache.org/licenses/LICENSE-2.0>).

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this module by you shall be licensed as
above, without any additional terms or conditions.

---

<p align="center">
  <sub>Built with the BEAM's protocol, ported to Go. <a href="https://github.com/sponsors/rgfaber">Sponsor the work</a> if this saved you some time</sub>
</p>
