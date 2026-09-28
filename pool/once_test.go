package pool

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// twoStationProviders is two providers serving procedure with the one offer,
// each from its own station, the stations sharing a DHT, so a caller finds
// two candidates; and a caller linked to the first station. (A node that
// advertised from both stations would hold one DHT slot, one candidate.)
func twoStationProviders(t *testing.T, name string, offer Offer) (caller *Pool, realm teststation.Realm) {
	t.Helper()
	a, b := teststation.Start(t, profile.PQPure, name+" a"), teststation.Start(t, profile.PQPure, name+" b")
	teststation.ShareDHT(a, b)
	realm = teststation.NewRealm(t, profile.PQPure, name, org)
	realm.Admit(t, a, nodeIDOf(t, name+" provider a"))
	realm.Admit(t, b, nodeIDOf(t, name+" provider b"))
	offer.Realm, offer.Procedure = realm.ID, procedure
	for side, s := range map[string]*teststation.Station{"a": a, "b": b} {
		if _, err := connect(t, name+" provider "+side, realm, s).Serve(t.Context(), offer); err != nil {
			t.Fatalf("Serve: %v", err)
		}
	}
	caller = connect(t, name+" caller", realm, a)
	eventually(t, "both candidates", func() bool {
		found, err := caller.Providers(t.Context(), realm.ID, procedure)
		return err == nil && len(found) == 2
	})
	return caller, realm
}

// A CALL that has gone out is never sent again: a handler slower than one
// candidate's share of the deadline is entered once, and its answer returned,
// for the share bounds reaching a station, not the call (macula's call_work
// and failure_scope/1). A retry would run a handler that is not idempotent
// twice (macula-go#8).
func TestACallThatWentOutIsNeverSentAgain(t *testing.T) {
	var entered atomic.Int32
	slow := func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
		entered.Add(1)
		time.Sleep(2500 * time.Millisecond)
		return r.Payload, nil
	}
	caller, realm := twoStationProviders(t, "once", Offer{Handler: slow})
	result, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello"),
		Timeout: 4 * time.Second})
	if text, _ := result.AsText(); err != nil || text != "hello" {
		t.Errorf("Call: %q, %v, want the one provider's answer", text, err)
	}
	time.Sleep(time.Second)
	if n := entered.Load(); n != 1 {
		t.Errorf("the handler was entered %d times, want once", n)
	}
}

// A stream the link refuses is not walked to the next candidate: every
// candidate would refuse it alike, as macula scopes open_too_large to the
// request.
func TestAStreamTheLinkRefusesIsNotWalked(t *testing.T) {
	var entered atomic.Int32
	caller, realm := twoStationProviders(t, "once stream", Offer{Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error {
			entered.Add(1)
			return s.Close()
		}}})
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
	defer cancel()
	_, err := caller.OpenStream(ctx, StreamCall{Realm: realm.ID, Procedure: procedure, Mode: frame.ServerStream,
		Payload: cbor.Text(strings.Repeat("x", 2<<20))})
	if !errors.Is(err, stationlink.ErrStreamOpenTooLarge) || errors.Is(err, ErrNoProvider) {
		t.Errorf("OpenStream: %v, want ErrStreamOpenTooLarge alone", err)
	}
	if n := entered.Load(); n != 0 {
		t.Errorf("the handler was entered %d times", n)
	}
}
