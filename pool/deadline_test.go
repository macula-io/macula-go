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

// lagging is a context whose deadline has passed while its timer has not yet
// fired: Deadline is in the past, Done is open and Err is nil. That is the
// state #12 is about, and the one a guard reading only ctx.Err misses.
type lagging struct {
	context.Context
	at time.Time
}

func (c lagging) Deadline() (time.Time, bool) { return c.at, true }

// A candidate reached only once the caller's deadline has passed, as a link
// coming up at the very end of the last share is, is never called: no CALL or
// STREAM_OPEN goes out with a provider deadline past its caller's, where the
// provider would run a request its caller has given up on (macula-go#12).
// Both a context whose timer has not fired yet and one already done are
// refused.
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
	done, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Millisecond))
	defer cancel()
	lag := lagging{t.Context(), time.Now().Add(-time.Millisecond)}
	if lag.Err() != nil {
		t.Fatal("the lagging context must not be done")
	}
	for name, past := range map[string]context.Context{"lagging": lag, "done": done} {
		if _, _, err := caller.callAt(past, link, calls[0], Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("late")}, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s callAt: %v, want the caller's deadline", name, err)
		}
		if _, err := caller.openAt(past, link, streams[0], StreamCall{Realm: realm.ID, Procedure: streamProcedure, Mode: frame.ServerStream, Payload: cbor.Map(nil)}, nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("%s openAt: %v, want the caller's deadline", name, err)
		}
	}
	time.Sleep(time.Second)
	if n := entered.Load(); n != 0 {
		t.Errorf("a handler was entered %d times after its caller's deadline", n)
	}
}
