# macula-go

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-go/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-go/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)
[![Go Reference](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev)
[![no unsafe](https://img.shields.io/badge/unsafe-none-success.svg)](https://pkg.go.dev/unsafe)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow.svg)](https://buymeacoffee.com/rlefever)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-go-full-dark.svg">
    <img src="assets/macula-go-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Go port of the Macula SDK wire protocol</strong>
</p>

---

> **Status, 2026-08-30:** the FULL wire protocol is built and
> **live-verified against the production station fleet**
> (`station-de-frankfurt.macula.io`) — handshake, unary RPC (both caller
> AND provider), PubSub, content transfer, and streaming RPC, every
> primitive in both caller and provider roles where the protocol has
> one. Beyond the base protocol: **direct-dial** (resolve a service via
> the mesh DHT and dial it in one hop, no dependency on inter-station
> routing gossip having propagated — covers RPC, streaming, and content
> transfer, plain and cert-chain-authorized), **periodic re-advertise**,
> a **supervised PubSub pair**, **UCAN** capability tokens (mint/verify/
> introspect, policy-gated serving), and automatic **RPC telemetry
> facts**. The frame layer is cross-checked byte-for-byte — including
> the Ed25519 signature itself — against
> [`macula-rust-sdk`](https://github.com/macula-io/macula-rust-sdk)'s own
> fixed reference vector. See [Status](#status) for the full picture.

## What is this?

A Go implementation of the client half of Macula's wire protocol — the
same protocol [`macula-io/macula`](https://github.com/macula-io/macula)
(the Erlang/OTP SDK) speaks, and the same protocol
[`macula-rust-sdk`](https://github.com/macula-io/macula-rust-sdk) already
ports, tracked in the same spec
([`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md), carried
over rather than re-derived — the wire protocol isn't language-specific).
Macula is a federated mesh for sovereign, end-to-end-encrypted
application networks; a **station** is the relay/DHT node, and this
module is what a **leaf** — anything that isn't itself a station — uses
to join it.

## Why a third implementation matters

Three independent implementations (Erlang reference, Rust, now Go)
producing bit-identical wire bytes for the same input is a much stronger
correctness claim than any one of them alone: `frame/reference_vector_test.go`
builds the exact same signed CONNECT frame as `macula-rust-sdk`'s own
test, from the exact same fixed identity/frame_id/timestamp, and asserts
the Ed25519 signature — not just the frame shape — matches byte for
byte. If Go's canonical CBOR encoder or signing domain diverged from the
other two anywhere, this would fail; it doesn't.

## Features

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Handshake (CONNECT/HELLO) | ✅ | — | Ed25519 identity, S/Kademlia puzzle-hardened; live-verified |
| Deterministic CBOR codec | ✅ | — | Hand-rolled — see [Codec](#the-cbor-codec-is-hand-rolled-on-purpose) |
| Unary RPC (CALL/RESULT/ERROR) | ✅ | ✅ | `Session.ServeOneCall`, BOLT#4 error mapping live-verified |
| PubSub (PUBLISH/SUBSCRIBE/EVENT) | ✅ | ✅ | A subscriber gets its own publish, verified live |
| Content transfer (single-block + chunked) | ✅ | ✅ | Content-addressed, BLAKE3/SHA-256, Merkle-verified |
| Streaming RPC (STREAM_OPEN/DATA/END/REPLY) | ✅ | ✅ | Both roles live-verified against the real fleet; `ClientStream` mode's reply path is SDK-correct but currently blocked by a `macula-station` bug — see [Known limitations](#known-limitations) |
| RPC advertise/unadvertise | ✅ | — | |
| Pubkey-pinned trust | ✅ | — | `transport.Pinned` — Ed25519 SPKI match, no CA chain needed |
| Direct-dial (`directdial`) | ✅ | ✅ | Resolve+dial via the mesh DHT, one hop, no routing-gossip dependency — RPC, streaming, content transfer; plain and cert-chain-authorized (`*WithCertChain`) |
| Periodic re-advertise | ✅ | — | `Session.KeepAdvertised`, `directdial.KeepAdvertisedDirect` — a station's registration doesn't survive the connection that sent it being replaced |
| Supervised PubSub pair | ✅ | ✅ | `Session.RunPublisher`/`RunSubscriber` — a managed alternative to the bare primitives above |
| UCAN capability tokens (`ucan`) | ✅ | ✅ | Mint/verify/introspect + policy-gated serving (`ServeOneCallGated`, `CallWithUCAN`) |
| Cert-chain org/realm authorization | ✅ | ✅ | `dht.VerifyAdvertisementCertChain` — opt-in, downstream of direct-dial |
| RPC telemetry facts | ✅ | ✅ | `rpc.sent_v1`/`rpc.completed_v1` (caller), `rpc.received_v1`/`rpc.replied_v1` (provider) — automatic, fire-and-forget, published under the call's own realm |

No `unsafe` anywhere in this module — the badge above is checked, not
aspirational (`grep -rl '"unsafe"' --include='*.go'` comes back empty).

## Quick start

Also lives as a runnable example — `go run ./examples/quickstart`:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

func main() {
	// Puzzle-hardened identity — required. An unhardened identity fails
	// the handshake silently (QUIC/TLS looks healthy, HELLO never accepts).
	id, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := connection.Connect(ctx, "station-de-frankfurt.macula.io", 4433, transport.WebPKI{}, id)
	if err != nil {
		log.Fatalf("connection.Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	realm := make([]byte, 32)
	deadlineMs := time.Now().Add(5 * time.Second).UnixMilli()
	response, err := session.Call("io.macula.echo", realm, cbor.Text("hello"), deadlineMs, id, 5*time.Second)
	if err != nil {
		log.Fatalf("session.Call: %v", err)
	}
	fmt.Printf("call response: is_error=%v payload=%s\n", response.IsError, response.Payload)
}
```

Content transfer and streaming RPC follow the same `*connection.Session`
plus an identity shape — see `content.Put`/`content.Get` and
`stream.Open`/`stream.Accept`, exercised end to end (both against the
real fleet) in `content/live_test.go` and `stream/live_test.go`.

Serving a procedure looks like this — `Session.ServeOneCall` blocks for
the next inbound CALL and replies with the handler's result (or the
matching BOLT#4 error on a lookup miss or a handler panic):

```go
lookup := func(realm []byte, procedure string) (connection.CallHandler, bool) {
	if procedure != "math.add" {
		return nil, false
	}
	return func(payload cbor.Value) (cbor.Value, error) {
		a, _ := payload.Get("a")
		b, _ := payload.Get("b")
		aVal, _ := a.AsInt64()
		bVal, _ := b.AsInt64()
		return cbor.Int(aVal + bVal), nil
	}, true
}

if err := session.Advertise(frame.NewAdvertiseSpec(realm, "math.add", id.NodeID()), id); err != nil {
	log.Fatal(err)
}
for {
	if err := session.ServeOneCall(lookup, id, 30*time.Second); err != nil {
		log.Println(err) // ErrServeOneCallTimeout just means nothing arrived
	}
}
```

## Direct-dial

Ordinary `Advertise`/`Call` depend on inter-station routing gossip having
already propagated a route between the caller's station and the
service's station — on a large or freshly-changed mesh, that isn't
always true yet. Direct-dial sidesteps it: a provider publishes a signed
record to the mesh DHT naming its own station; a caller resolves that
record and dials the named station **directly, in one hop**, regardless
of whether ordinary gossip ever reached the caller's own station.

```go
// Provider: advertise once, then keep the DHT record fresh (a station's
// registration doesn't survive the connection that sent it being replaced).
if err := directdial.AdvertiseDirect(session, id, realm, "math.add", time.Hour); err != nil {
	log.Fatal(err)
}
ctx, cancel := context.WithCancel(context.Background())
defer cancel()
directdial.KeepAdvertisedDirect(ctx, session, id, realm, "math.add", time.Hour, 30*time.Second,
	func(err error) { log.Printf("re-advertise tick failed: %v", err) })

if err := session.ServeOneCall(lookup, id, 30*time.Second); err != nil {
	log.Println(err)
}
```

```go
// Caller: resolveVia can be a connection to ANY station — it's only used
// to query the DHT, not necessarily the station actually serving the call.
resp, err := directdial.Call(ctx, resolveVia, id, realm, "math.add", cbor.Text("hello"), 10*time.Second)
```

The same resolve-and-dial mechanism covers streaming (`directdial.OpenStreamDirect`)
and content transfer (`directdial.PutDirect`/`GetDirect`), and each has a
`*WithCertChain` variant that additionally requires the resolved
advertisement's embedded X.509 chain to validate against a caller-trusted
realm CA and name an expected org (`dht.VerifyAdvertisementCertChain`) —
opt-in managed-realm authorization, layered on top of direct-dial rather
than replacing it. `directdial.GetDirect`'s publish side
(`dht.NewContentAnnouncement`) is deliberately not exposed as a
client-facing function: unlike a `procedure_advertisement`, a
`content_announcement`'s resolved endpoint is dialed with no
station-relay indirection, so only something independently dialable (a
station or dedicated relay) can legitimately publish one — a leaf
identity can't pass its own trust check.

## UCAN capability tokens

A service can require callers to present a signed capability token
before a handler ever runs:

```go
// Mint (typically done by whoever issues capabilities, not the caller
// of ServeOneCallGated):
token, err := ucan.Create("did:macula:issuer", "did:macula:audience", nil, issuerID, ucan.CreateOpts{})

// Provider: gate one (realm, procedure) behind a required issuer. An
// open Policy (the zero value, ucan.Open) behaves exactly like plain
// ServeOneCall — rejection happens BEFORE lookup/dispatch, so a handler
// never sees the raw token either way.
policy := func(realm []byte, procedure string) ucan.Policy {
	return ucan.Required(issuerID.NodeID())
}
if err := session.ServeOneCallGated(lookup, policy, id, 30*time.Second); err != nil {
	log.Println(err)
}

// Caller: attach the token to an outgoing call.
resp, err := session.CallWithUCAN("gated.procedure", realm, payload, deadlineMs, id, timeout, token)
```

`ucan.Create`/`Verify`/`Decode`/`GetIssuer`/`GetAudience`/`GetCapabilities`/
`GetExpiration`/`GetProofs`/`IsExpired` mirror `macula_ucan_nif`'s exact
surface (JWT-shaped UCAN 0.10.0, EdDSA) — no more, no less. `issuer`/
`audience` are opaque DID strings; this package doesn't validate or
resolve DID structure (that's `macula_did_nif`'s scope on the Erlang
side).

## The CBOR codec is hand-rolled on purpose

This protocol's canonical CBOR **deliberately diverges** from RFC 8949's
own canonical-form guidance in two ways: floats always encode as
binary64 (never the shortest round-tripping width), and map keys sort
by the bytewise order of their own *encoded* bytes, not their unencoded
representation. A generic "canonical CBOR" library that follows the RFC
instead of these rules produces bytes that don't verify against the
real station — the same reason `macula-rust-sdk` bypasses `ciborium`
entirely. `cbor/` has zero external dependencies as a result; the tests
in `cbor/cbor_test.go` specifically target the divergent rules and the
minimal-length-encoding boundaries a naive port is most likely to get
wrong.

## Testing

```bash
go test ./...                                       # default suite, no network
go test -tags=live ./... -run TestLive -v            # dials the real fleet
```

The live suite is gated behind the `live` build tag — excluded from
`go test ./...` and from CI entirely, since it depends on infrastructure
this module doesn't control and a station blip must never block an
unrelated PR. Same convention as `macula-rust-sdk`'s `tests/live_station.rs`.

## Known limitations

- **`frame.ClientStream` mode's reply path (`SendReply`/`AwaitReply`) is
  correct on this SDK's side but currently blocked by a `macula-station`
  bug.** `stream/live_test.go`'s `TestLiveClientStreamReplyRoundTrip`
  reproduces it reliably: the provider receives the caller's data and
  end-of-stream correctly and `SendReply` returns no error, but the
  caller's `AwaitReply` gets a raw transport EOF. Root cause is on the
  relay side — the caller and provider each hold a separate dedicated
  QUIC stream to the station, bridged by the station's own relay logic,
  and the station appears to close the caller-facing leg's write side as
  soon as it relays the caller's `STREAM_END`, before the provider's
  reply can flow back the other way. Not fixable in this module. The
  test skips with a clear diagnostic rather than failing, so it stops
  blocking CI without losing the regression check.
- **`directdial.GetDirect` can only resolve a `content_announcement`
  that something has actually published** — and nothing in this
  ecosystem currently does, since (per the design note above) only a
  station/relay can legitimately publish one. Treat `GetDirect` as
  correct-but-currently-unreachable until a relay-side publisher exists.
- The demo fleet's `station_endpoint` DHT records carry a short TTL and
  are not always freshly republished — a direct-dial resolve can
  intermittently return `ErrStationEndpointNotFound` for a station whose
  procedure/service is otherwise healthy. Retrying against a different
  station, or shortly after, typically clears it. This is fleet
  infrastructure state, not a bug in this module.

## Status

**Live-verified, 2026-08-28 — full parity, both directions:** handshake,
CALL/RESULT/ERROR as both caller (`Session.Call`) and provider
(`Session.ServeOneCall`, BOLT#4 error mapping — `unknown_next_peer` on a
lookup miss, `temporary_relay_failure` on a handler panic, `unknown_error`
with detail on a handler-returned error, all ported field-for-field from
`macula_station_link.erl`'s `handle_inbound_call/2`), PUBLISH/SUBSCRIBE/
EVENT (a subscriber does receive its own publish), content transfer
(single-block and chunked, Merkle-verified), and streaming RPC in both
the caller and provider roles — all against
`station-de-frankfurt.macula.io`, the real fleet, not a local mock. Two
independent connections to the same station (one advertising and
serving, the other calling in) is the pattern behind every provider-role
test here — see `connection/live_test.go`'s
`TestLiveUnaryCallProviderRoundTrip` for the unary case and
`stream/live_test.go`'s `TestLiveStreamingProviderRoundTrip` for the
streaming case.

The streaming-RPC and content-transfer wire behavior was cross-checked
against `macula-rust-sdk`'s own live findings along the way — e.g. an
unregistered streaming procedure returns the same STREAM_ERROR
(`unknown_next_peer` / "procedure not advertised") on both SDKs.
Unary-RPC provider dispatch was built here first and ported back to
`macula-rust-sdk` in the same pass, so both SDKs now serve RPCs, not
just call them.

**Live-verified, 2026-08-30 — direct-dial, UCAN, cert-chain, re-advertise,
supervised PubSub, RPC telemetry facts:** every item above got the same
live-fleet treatment, and to a stricter bar than "no error was
returned" — `AdvertiseDirect` originally published only the DHT record
and never the plain ADVERTISE frame, which let `Resolve`+`Call` complete
cleanly without ever reaching a live handler; found by insisting on an
actual RESULT payload coming back through direct-dial rather than
accepting a clean `unknown_next_peer` as sufficient, and fixed
(`d18a079`). `TestLiveDirectDialServeRoundTrip`, `TestLiveKeepAdvertisedDirectRepublishes`,
`TestLiveRunSubscriberAndRunPublisher`, and `TestLiveRPCTelemetryFacts`
all hold to that same bar — a real reply payload, or a real fact
confirmed by an independent third session, not just an absence of
errors.

See [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md) for the
full wire-format spec this module is built against, section by section,
traced directly to the Erlang SDK's source.

## Related projects

| Project | Description |
|---|---|
| [macula-rust-sdk](https://github.com/macula-io/macula-rust-sdk) | The Rust port — same protocol, built first; also ships mobile bindings (Kotlin/Swift via UniFFI) |
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, SWIM, routing, peering |
| [macula-realm](https://github.com/macula-io/macula-realm) | Managed-realm identity + certificate authority |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this module by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

---

<p align="center">
  <sub>Built with the BEAM's protocol, ported to Go — <a href="https://buymeacoffee.com/rlefever">buy me a coffee</a> if this saved you some time</sub>
</p>
