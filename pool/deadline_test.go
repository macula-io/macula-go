package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// A candidate reached only once the caller's deadline has passed, as a link
// coming up at the very end of the last share is, is never called: nothing is
// written after the deadline, where the provider would run a request its
// caller has already been told failed (macula-go#12).
func TestNothingIsSentPastTheCallersDeadline(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "late")
	realm := teststation.NewRealm(t, profile.PQPure, "late", org)
	realm.Admit(t, s, nodeIDOf(t, "late provider"))
	var entered atomic.Int32
	provider := connect(t, "late provider", realm, s)
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			entered.Add(1)
			return r.Payload, nil
		}}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	streamProcedure := procedure + "_stream"
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: streamProcedure,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, st *stationlink.Stream) error {
			entered.Add(1)
			return st.Close()
		}}}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connect(t, "late caller", realm, s)
	realmKey, err := caller.realmKeyFor(realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	var calls, streams []candidate
	eventually(t, "both advertised", func() bool {
		calls, _ = caller.resolve(t.Context(), resolvedKey{realm: realm.ID, procedure: procedure}, realmKey)
		streams, _ = caller.resolve(t.Context(), resolvedKey{realm: realm.ID, procedure: streamProcedure}, realmKey)
		return len(calls) == 1 && len(streams) == 1
	})
	link, err := caller.linkTo(t.Context(), calls[0].Station)
	if err != nil {
		t.Fatalf("linkTo: %v", err)
	}
	past, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Millisecond))
	defer cancel()
	if _, err := caller.callAt(past, link, calls[0], Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("late")}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("callAt: %v, want the caller's deadline", err)
	}
	if _, err := caller.openAt(past, link, streams[0], StreamCall{Realm: realm.ID, Procedure: streamProcedure, Mode: frame.ServerStream, Payload: cbor.Map(nil)}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("openAt: %v, want the caller's deadline", err)
	}
	time.Sleep(time.Second)
	if n := entered.Load(); n != 0 {
		t.Errorf("a handler was entered %d times after its caller's deadline", n)
	}
}
