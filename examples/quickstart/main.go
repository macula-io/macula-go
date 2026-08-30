// Minimal end-to-end example: connect to a real macula-station,
// complete the handshake, and make one unary CALL. Dials the real
// fleet, so this isn't run by CI — see README.md's "Quick start"
// section, which this file backs (kept compiling by `go build ./...`
// in CI, run manually with `go run ./examples/quickstart`).
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

	realm := make([]byte, 32)
	deadlineMs := time.Now().Add(5 * time.Second).UnixMilli()
	response, err := session.Call("io.macula.echo", realm, cbor.Text("hello"), deadlineMs, id, 5*time.Second)
	if err != nil {
		log.Fatalf("session.Call: %v", err)
	}
	fmt.Printf("call response: is_error=%v payload=%s\n", response.IsError, response.Payload)
}
