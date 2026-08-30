// Command ucan demonstrates minting a UCAN capability token and gating a
// served procedure behind it: an unauthorized call is refused before any
// handler code runs, and a call carrying a valid token reaches it.
//
// Run: go run ./examples/ucan
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
	"github.com/macula-io/macula-go-sdk/ucan"
)

const (
	host      = "station-de-frankfurt.macula.io"
	port      = 4433
	procedure = "examples.ucan.gated"
)

func main() {
	providerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		log.Fatalf("identity.Generate (caller): %v", err)
	}

	// providerID doubles as the token issuer here -- the policy requires
	// a token signed by whichever key the provider decides to trust.
	token, err := ucan.Create("did:macula:example-issuer", "did:macula:example-audience", nil, providerID, ucan.CreateOpts{})
	if err != nil {
		log.Fatalf("ucan.Create: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	provider, err := connection.Connect(ctx, host, port, transport.WebPKI{}, providerID)
	if err != nil {
		log.Fatalf("connection.Connect (provider): %v", err)
	}
	defer provider.Close("normal", nil, providerID)

	realm := make([]byte, 32)
	if err := provider.Advertise(frame.NewAdvertiseSpec(realm, procedure, providerID.NodeID()), providerID); err != nil {
		log.Fatalf("Advertise: %v", err)
	}

	// Gate the procedure: only a caller presenting a token signed by
	// providerID's own key is let through to lookup/dispatch. A rejected
	// call never reaches the handler below.
	policy := func(_ []byte, _ string) ucan.Policy { return ucan.Required(providerID.NodeID()) }
	lookup := func(_ []byte, proc string) (connection.CallHandler, bool) {
		if proc != procedure {
			return nil, false
		}
		return func(cbor.Value) (cbor.Value, error) {
			return cbor.Text("granted"), nil
		}, true
	}

	served := make(chan error, 2)
	go func() { served <- provider.ServeOneCallGated(lookup, policy, providerID, 15*time.Second) }()

	caller, err := connection.Connect(ctx, host, port, transport.WebPKI{}, callerID)
	if err != nil {
		log.Fatalf("connection.Connect (caller): %v", err)
	}
	defer caller.Close("normal", nil, callerID)

	// First call: no token. Refused with BOLT#4 Unauthorized before the
	// handler above ever runs.
	resp, err := caller.Call(procedure, realm, cbor.Null(), time.Now().Add(10*time.Second).UnixMilli(), callerID, 10*time.Second)
	if err != nil {
		log.Fatalf("Call (no token): %v", err)
	}
	fmt.Printf("call without a token: is_error=%v code=%d\n", resp.IsError, resp.Code)
	if err := <-served; err != nil {
		log.Fatalf("ServeOneCallGated (rejected call): %v", err)
	}

	// Second call: a valid token, served by a fresh ServeOneCallGated
	// (each blocks for exactly one inbound CALL).
	go func() { served <- provider.ServeOneCallGated(lookup, policy, providerID, 15*time.Second) }()
	resp, err = caller.CallWithUCAN(procedure, realm, cbor.Null(), time.Now().Add(10*time.Second).UnixMilli(), callerID, 10*time.Second, token)
	if err != nil {
		log.Fatalf("CallWithUCAN: %v", err)
	}
	fmt.Printf("call with a valid token: is_error=%v payload=%s\n", resp.IsError, resp.Payload)
	if err := <-served; err != nil {
		log.Fatalf("ServeOneCallGated (authorized call): %v", err)
	}
}
