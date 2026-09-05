// Minimal end-to-end example: connect to a real macula-station, complete
// the handshake, advertise a trivial echo procedure, and call it. Dials
// the real fleet, so this isn't run by CI -- see README.md's "Quick
// start" section, which this file backs (kept compiling by `go build
// ./...` in CI, run manually with `go run ./examples/quickstart`).
//
// Two identities are used (a provider and a caller) because a station
// kicks a connection the instant a second one arrives under the same
// identity -- the same reason every one of this SDK's own live tests
// uses separate identities for each role. The procedure name is unique
// per run (a station's DHT can hold stale routing state for a fixed
// name from a prior run's now-dead advertiser) -- and it's this SDK's
// own procedure, not a shared fleet service, so this example never
// depends on anything else being deployed.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

func main() {
	// Puzzle-hardened identities -- required. An unhardened identity fails
	// the handshake silently in the worst case (QUIC/TLS looks healthy,
	// HELLO never accepts).
	providerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (caller): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	provider, err := connection.Connect(ctx, "station-de-frankfurt.macula.io", 4433, transport.WebPKI{}, providerID)
	if err != nil {
		log.Fatalf("connection.Connect (provider): %v", err)
	}
	defer provider.Close("normal", nil, providerID)

	realm := make([]byte, 32)
	procedure := fmt.Sprintf("macula_go.quickstart_echo.%d", time.Now().UnixNano())

	lookup := func(realm []byte, proc string) (connection.CallHandler, bool) {
		if proc != procedure {
			return nil, false
		}
		return func(payload cbor.Value) (cbor.Value, error) {
			return payload, nil
		}, true
	}

	if err := provider.Advertise(frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID()), providerID); err != nil {
		log.Fatalf("provider.Advertise: %v", err)
	}
	time.Sleep(500 * time.Millisecond) // ADVERTISE is fire-and-forget; give it a moment to land

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- provider.ServeOneCall(lookup, providerID, 10*time.Second)
	}()

	caller, err := connection.Connect(ctx, "station-de-frankfurt.macula.io", 4433, transport.WebPKI{}, callerID)
	if err != nil {
		log.Fatalf("connection.Connect (caller): %v", err)
	}
	defer caller.Close("normal", nil, callerID)

	deadlineMs := time.Now().Add(5 * time.Second).UnixMilli()
	response, err := caller.Call(procedure, realm, cbor.Text("hello"), deadlineMs, callerID, 5*time.Second)
	if err != nil {
		log.Fatalf("caller.Call: %v", err)
	}
	fmt.Printf("call response: is_error=%v payload=%s\n", response.IsError, response.Payload)

	if err := <-serveErr; err != nil {
		log.Fatalf("provider.ServeOneCall: %v", err)
	}
}
