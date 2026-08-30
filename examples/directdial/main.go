// Command directdial demonstrates resolving and calling a service via the
// mesh DHT in one hop, instead of depending on inter-station routing
// gossip having already propagated a route.
//
// Run: go run ./examples/directdial
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/directdial"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

const (
	host      = "station-de-frankfurt.macula.io"
	port      = 4433
	procedure = "examples.directdial.add"
)

func main() {
	// Two SEPARATE identities: this fleet enforces one connection per
	// identity and kicks whichever connects second, so a provider and a
	// caller must never share one.
	providerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (caller): %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := connection.Connect(ctx, host, port, transport.WebPKI{}, providerID)
	if err != nil {
		log.Fatalf("connection.Connect (provider): %v", err)
	}
	defer provider.Close("normal", nil, providerID)

	realm := make([]byte, 32)

	// Publishes BOTH the plain ADVERTISE frame and the signed DHT record
	// naming this station as the server — a caller can reach this
	// procedure through ordinary gossip-routed advertise/call too, direct
	// dial is what lets it work even when that hasn't propagated yet.
	if err := directdial.AdvertiseDirect(provider, providerID, realm, procedure, time.Hour); err != nil {
		log.Fatalf("AdvertiseDirect: %v", err)
	}

	served := make(chan error, 1)
	go func() {
		lookup := func(_ []byte, proc string) (connection.CallHandler, bool) {
			if proc != procedure {
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
		served <- provider.ServeOneCall(lookup, providerID, 20*time.Second)
	}()

	caller, err := connection.Connect(ctx, host, port, transport.WebPKI{}, callerID)
	if err != nil {
		log.Fatalf("connection.Connect (caller): %v", err)
	}
	defer caller.Close("normal", nil, callerID)

	// caller only needs a connection to SOME station to query the DHT --
	// it does not need to be the same station serving the call.
	args := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Int(3)},
		{Key: cbor.Text("b"), Val: cbor.Int(4)},
	})
	resp, err := directdial.Call(ctx, caller, callerID, realm, procedure, args, 15*time.Second)
	if err != nil {
		log.Fatalf("directdial.Call: %v", err)
	}
	if resp.IsError {
		log.Fatalf("call returned an error frame: code=%d", resp.Code)
	}
	fmt.Printf("direct-dial call result: %s\n", resp.Payload)

	if err := <-served; err != nil {
		log.Fatalf("ServeOneCall: %v", err)
	}
}
