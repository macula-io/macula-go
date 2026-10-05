# macula-go

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-go/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-go/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](#license)
[![Go Reference](https://img.shields.io/badge/go-1.27%2B-00ADD8?logo=go)](https://go.dev)
[![memory safety](https://img.shields.io/badge/memory%20safety-no%20unsafe%20or%20cgo-success.svg)](https://pkg.go.dev/unsafe)
[![GitHub Sponsors](https://img.shields.io/badge/GitHub%20Sponsors-support-ea4aaa.svg?logo=githubsponsors&logoColor=white)](https://github.com/sponsors/rgfaber)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-go-full-dark.svg">
    <img src="assets/macula-go-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Go port of the Macula SDK, on the macula 12 wire: TLS 1.3 with a hybrid post-quantum key exchange, and ML-DSA-87 signatures</strong>
</p>

---

> **Status, 2026-09-29:** master speaks the **macula 12** wire and nothing
> older. Handshake, calls, streaming RPC, publish/subscribe, the DHT, serving
> procedures (under an org or in a node's own namespace) and node-served
> content work against live macula stations, including calls and streams by
> direct dial from one node to another's provider. Content is shared and
> fetched both ways with macula 12.6.0's Erlang sharer and fetcher. Manifests
> and MCIDs are macula 12's, byte for byte. Calls and streams are sealed end
> to end as macula 13 seals them (scheme 1), checked both ways against
> macula 13.0.0 in `pq_pure` and `pq_hybrid`. On master, links speak macula
> 13.2.0's handshake v5, bound to the TLS session, and fall back to v4 once
> for a station before 13.2.0; checked live against macula 13.2.1 from hex.pm
> in both profiles and both directions (v0.20.0).

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
- **Frames:** requests, replies, publications and records are signed
  objects. On a handshake v5 link (macula 13.2.0) the connection is
  authenticated once, by hybrid proofs bound to its TLS session, and no control
  frame carries a neighbour signature; on a v4 link, to a station before 13.2.0,
  every control frame in `pq_hybrid` is neighbour-signed.

## Features

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Handshake v5, and v4 (OPENER, CHALLENGE, CONNECT, HELLO, STATUS) | ✅ | — | `stationlink.Dial`, the station pinned by node_id: v5 bound to the TLS exporter, v4 once after a station refuses v5; a station seen on v5 that answers v4 is refused (`ErrV5DowngradeRefused`, `ForgetV5Peer`); `HandshakeCounters`. Checked live against macula 13.2.0's station in `pq_pure` and `pq_hybrid` |
| Deterministic CBOR codec and decoding rule | ✅ | ✅ | Hand-rolled, see [Codec](#the-cbor-codec-is-hand-rolled-on-purpose) |
| Unary RPC (signed CALL, RESULT, ERROR) | ✅ | ✅ | `pool.Call` by direct dial; `pool.Serve` answers with `handler_error`, `temporary_relay_failure` or `unknown_next_peer` |
| Request admission | — | ✅ | Deadline window, each request run once, a copy answered from the stored reply, bounded as macula bounds it |
| Provider authorization | ✅ | ✅ | The realm's org directory and the org's delegation, checked against the realm key the pool pins |
| A node's own namespace (`~<node_id>/<name>`) | ✅ | ✅ | No authorization and no realm key: the advertisement's signature by that node authorizes it; checked against macula's shared fixtures |
| PubSub (signed PUBLISH, SUBSCRIBE, EVENT) | ✅ | ✅ | Published once over several links, delivered once |
| DHT (`_dht.*`) | ✅ | — | Records verified before they are handed on |
| Pool of station links | ✅ | ✅ | Pinned seeds, redial with subscriptions and procedures replayed |
| Streaming RPC (server, client and bidi streams) | ✅ | ✅ | A QUIC stream per session; `pool.OpenStream` by direct dial, `Offer.Stream` to serve; admission, session and inbox bounds as macula's; every stream released on every path |
| Content manifests and MCIDs | ✅ | ✅ | SHA-384, 50-byte MCIDs, byte for byte with macula's `macula_manifest` |
| Node-served content (D27) | ✅ | ✅ | `pool.ShareContent` serves on `~<node_id>/content_v1` and announces; `pool.GetContent` checks the block, the manifest and every chunk against their content ids, bounded, with no realm key; cross-checked both ways against macula 12.6.0 |
| Gated procedures (UCAN) | ✅ | ✅ | `ucan.Create` mints macula 12's post-quantum UCAN, `Call.Token` and `Proofs` present it and its chain, `Offer.Policy` gates a procedure as macula's link does (`unauthorized`, or `malformed_frame` for a proof no token names); held to macula's UCAN vectors and checked against `macula_ucan` both ways |
| End-to-end sealing (macula 13, scheme 1) | ✅ | ✅ | A call's or a stream's payloads sealed to the KEM key the provider's advertisement names, so a station routes what it cannot read; see [Sealing](#sealing) |

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
| [`teststation`](teststation) | In-process macula 13.2.0 stations for tests (handshake v5 and v4); `teststation/cmd/teststation` serves them to a binding's tests |
| [`ucan`](ucan) | macula 12's UCAN: mint, verify a chain against a policy, proof ids and did:keys, held to macula's vectors |
| [`devicerequest`](devicerequest) | A device's request to a realm, signed: realm proof v2 (macula-realm#29) |
| [`ownershipproof`](ownershipproof) | The `asserted_by` block of a payload, signed and verified: ownership proof v2 (mcl-om#7) |
| [`seal`](seal) | End-to-end payload sealing, scheme 1: the key agreement, keys, AAD and AES-256-GCM, and a provider's keyring, held to macula 13's vectors |

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

`KEMAdvertise` is off by default. Switch it on only once every station runs
macula 12.11 or later, which stores and routes a keyed advertisement, and
every caller runs macula 13 or macula-go 0.18 (the station floor). The fleet's
stations meet it (macula-station 0.6.8, on macula 12.11.1).

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

The suite needs no network. The pool is tested against
[`teststation`](teststation), an in-process macula 12
station that routes calls between connections, delivers events and holds a
DHT. It is public, so the SDKs built on macula-go (such as @macula-io/ts)
test against the same station.

Checks against a compiled macula, in both directions (key bindings, the LAMPS
composite, the handshake, neighbour signatures), and against a live station
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
