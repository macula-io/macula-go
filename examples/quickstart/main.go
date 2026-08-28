// Minimal end-to-end example: connect to a real macula-station and
// complete the handshake. Dials the real fleet, so this isn't run by
// CI — see README.md's "Quick start" section, which this file backs
// (kept compiling by `go build ./...` in CI, run manually with
// `go run ./examples/quickstart`).
//
// This is a handshake-only example on purpose: RPC/PubSub/content
// transfer aren't built yet (see README.md's Status section) — a
// call/publish example will follow the same shape once they land, the
// same way macula-rust-sdk's own quick start does today.
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
	defer session.Close("normal", nil, id)

	fmt.Printf("connected: remote=%s accepted=%v station_id=%x negotiated_capabilities=%d\n",
		session.RemoteAddr(), session.Station.Accepted, session.Station.StationID,
		session.Station.NegotiatedCapabilities)
}
