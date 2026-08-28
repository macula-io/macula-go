# macula-go-sdk

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-go-sdk/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-go-sdk/actions/workflows/ci.yml)
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

> **Status, 2026-08-28:** walking skeleton, **live-verified against the
> production station fleet** (`station-de-frankfurt.macula.io`):
> deterministic CBOR, Ed25519 identity, the frame envelope, QUIC/TLS
> transport, and the CONNECT/HELLO handshake. The frame layer is
> cross-checked byte-for-byte — including the Ed25519 signature itself
> — against [`macula-rust-sdk`](https://github.com/macula-io/macula-rust-sdk)'s
> own fixed reference vector. RPC, PubSub, content transfer, and
> streaming RPC aren't built yet — see [Status](#status).

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

| Primitive | Status | Notes |
|---|---|---|
| Handshake (CONNECT/HELLO) | ✅ | Ed25519 identity, S/Kademlia puzzle-hardened; live-verified |
| Deterministic CBOR codec | ✅ | Hand-rolled — see [Codec](#the-cbor-codec-is-hand-rolled-on-purpose) |
| Unary RPC (CALL/RESULT/ERROR) | ⏳ | Not yet built |
| PubSub (PUBLISH/SUBSCRIBE/EVENT) | ⏳ | Not yet built |
| Content transfer | ⏳ | Not yet built |
| Streaming RPC | ⏳ | Not yet built |

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

	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

func main() {
	// Puzzle-hardened identity — required. An unhardened identity fails
	// the handshake silently in the worst case (QUIC/TLS looks healthy,
	// HELLO never accepts).
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
	defer session.Close()

	fmt.Printf("connected: remote=%s accepted=%v station_id=%x\n",
		session.RemoteAddr(), session.Station.Accepted, session.Station.StationID)
}
```

Handshake-only on purpose — RPC/PubSub/content transfer aren't built
yet. A call/publish example will follow the same shape once they land,
matching `macula-rust-sdk`'s own quick start.

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
go test ./...                                          # default suite, no network
go test -tags=live ./connection/... -run TestLive -v   # dials the real fleet
```

The live suite is gated behind the `live` build tag — excluded from
`go test ./...` and from CI entirely, since it depends on infrastructure
this module doesn't control and a station blip must never block an
unrelated PR. Same convention as `macula-rust-sdk`'s `tests/live_station.rs`.

## Status

**Live-verified, 2026-08-28:** the CONNECT/HELLO handshake, against
`station-de-frankfurt.macula.io` — the real fleet, not a local mock —
via both `connection/live_test.go` and `examples/quickstart`.

**Not yet built** (tracked in the order `macula-rust-sdk` built them):
- Unary RPC (CALL/RESULT/ERROR)
- PubSub (PUBLISH/SUBSCRIBE/EVENT)
- Content transfer (single-block + chunked)
- Streaming RPC (both caller and provider roles)

See [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md) for the
full wire-format spec this module is built against, section by section,
traced directly to the Erlang SDK's source.

## Related projects

| Project | Description |
|---|---|
| [macula-rust-sdk](https://github.com/macula-io/macula-rust-sdk) | The Rust port — same protocol, built first, further along |
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
