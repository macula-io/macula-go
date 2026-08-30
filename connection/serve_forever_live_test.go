//go:build live

package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// TestLiveServeOneCallGatedTimeoutReturnsSentinel pins the bug fixed
// alongside ServeForever: a tick with nothing arriving must return
// ErrServeOneCallTimeout (as errors.Is, not just "some non-nil error"),
// since ServeForever's own loop depends on that sentinel to tell
// "nothing happened, keep going" apart from "the connection died".
func TestLiveServeOneCallGatedTimeoutReturnsSentinel(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	noHandlers := func(_ []byte, _ string) (CallHandler, bool) { return nil, false }
	start := time.Now()
	err = session.ServeOneCallGated(noHandlers, openPolicy, id, 3*time.Second)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrServeOneCallTimeout) {
		t.Fatalf("ServeOneCallGated with nothing arriving: err=%v, want errors.Is(err, ErrServeOneCallTimeout)", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took %s to time out against a 3s tick -- sentinel path may be falling through to a longer wait", elapsed)
	}
}

func randomServeForeverProcedure(t *testing.T, suffix string) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("macula_go_sdk.test_serve_forever.%s.%s", suffix, hex.EncodeToString(b))
}

// TestLiveServeForeverAnswersMultipleCallsAcrossDynamicRegistration
// proves the actual daemon shape ServeForever exists for: one Session
// answers several CALLs in a row (not just one, unlike ServeOneCall),
// and a procedure registered AFTER the loop has already started is
// reachable on the very next call -- exactly what a daemon's
// serve.register RPC needs (mutating the map a running ServeForever's
// lookup closure reads, no restart involved).
func TestLiveServeForeverAnswersMultipleCallsAcrossDynamicRegistration(t *testing.T) {
	providerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (provider): %v", err)
	}
	callerID, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate (caller): %v", err)
	}
	realm := randomBytes(t, 32)

	connectCtx, connectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer connectCancel()
	provider, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, providerID)
	if err != nil {
		t.Fatalf("Connect (provider): %v", err)
	}
	defer provider.Close("normal", nil, providerID)
	caller, err := Connect(connectCtx, liveStationHost, liveStationPort, transport.WebPKI{}, callerID)
	if err != nil {
		t.Fatalf("Connect (caller): %v", err)
	}
	defer caller.Close("normal", nil, callerID)

	var mu sync.Mutex
	handlers := map[string]CallHandler{}
	register := func(procedure string, h CallHandler) {
		mu.Lock()
		defer mu.Unlock()
		handlers[procedure] = h
	}
	lookup := func(_ []byte, procedure string) (CallHandler, bool) {
		mu.Lock()
		defer mu.Unlock()
		h, ok := handlers[procedure]
		return h, ok
	}

	firstProc := randomServeForeverProcedure(t, "first")
	register(firstProc, func(payload cbor.Value) (cbor.Value, error) { return payload, nil })
	if err := provider.Advertise(frame.NewAdvertiseSpec(realm, firstProc, providerID.NodeID()), providerID); err != nil {
		t.Fatalf("Advertise (first): %v", err)
	}
	defer provider.Unadvertise(frame.NewUnadvertiseSpec(realm, firstProc, providerID.NodeID()), providerID)
	// Give the station a moment to register the advertisement before
	// calling it -- same settle wait TestLiveUnaryCallProviderRoundTrip
	// documents.
	time.Sleep(500 * time.Millisecond)

	loopCtx, loopCancel := context.WithCancel(context.Background())
	defer loopCancel()
	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- provider.ServeForever(loopCtx, lookup, openPolicy, providerID) }()

	// First call: only the first procedure is registered.
	resp1, err := caller.control.Call(firstProc, realm, cbor.Text("one"), nowMs()+10_000, callerID, 15*time.Second)
	if err != nil {
		t.Fatalf("Call (first): %v", err)
	}
	if resp1.IsError {
		t.Fatalf("Call (first): got ERROR frame, code=%d", resp1.Code)
	}
	got1, _ := resp1.Payload.AsText()
	if got1 != "one" {
		t.Fatalf("Call (first): payload = %q, want %q", got1, "one")
	}

	// Register a SECOND procedure while ServeForever is already
	// running, with no restart -- this is the exact operation a
	// daemon's serve.register control-socket RPC performs.
	secondProc := randomServeForeverProcedure(t, "second")
	register(secondProc, func(payload cbor.Value) (cbor.Value, error) { return payload, nil })
	if err := provider.Advertise(frame.NewAdvertiseSpec(realm, secondProc, providerID.NodeID()), providerID); err != nil {
		t.Fatalf("Advertise (second): %v", err)
	}
	defer provider.Unadvertise(frame.NewUnadvertiseSpec(realm, secondProc, providerID.NodeID()), providerID)
	time.Sleep(500 * time.Millisecond)

	resp2, err := caller.control.Call(secondProc, realm, cbor.Text("two"), nowMs()+10_000, callerID, 15*time.Second)
	if err != nil {
		t.Fatalf("Call (second): %v", err)
	}
	if resp2.IsError {
		t.Fatalf("Call (second): got ERROR frame, code=%d", resp2.Code)
	}
	got2, _ := resp2.Payload.AsText()
	if got2 != "two" {
		t.Fatalf("Call (second): payload = %q, want %q", got2, "two")
	}

	loopCancel()
	select {
	case err := <-serveErrCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("ServeForever after cancel: err=%v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("ServeForever did not return within 5s of ctx cancellation")
	}
}
