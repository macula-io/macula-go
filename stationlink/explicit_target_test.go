package stationlink_test

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
)

// A call or a stream to a provider states how it is kept (macula 13's
// call_seal/5, E2E design §8.1): sealed to a key (SealTo) or clear by the
// application's own decision (Clear). One that states neither is refused
// no_signed_state, and one that states both is refused, before anything is
// sent.
func TestAnExplicitTargetStatesSealedOrClear(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "explicit target")
	var entered atomic.Int32
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/open", Confidential: stationlink.ConfidentialOff,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			entered.Add(1)
			return r.Payload, nil
		}})
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/watch", Confidential: stationlink.ConfidentialOff,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			entered.Add(1)
			return s.Reply(cbor.Text("watched"))
		}}})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	call := stationlink.Call{Realm: w.realm.ID, Procedure: "mcl-vault/open", Target: w.provider.NodeID(), Payload: cbor.Text("x")}
	open := stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/watch", Target: w.provider.NodeID(),
		Mode: frame.ServerStream, Payload: cbor.Map(nil)}

	var unstated *stationlink.ConfidentialityError
	if _, err := w.caller.Call(ctx, call); !errors.As(err, &unstated) || unstated.Reason != stationlink.ReasonNoSignedState {
		t.Errorf("a call stating neither: %v, want no_signed_state", err)
	}
	if _, err := w.caller.OpenStream(ctx, open); !errors.As(err, &unstated) || unstated.Reason != stationlink.ReasonNoSignedState {
		t.Errorf("an open stating neither: %v, want no_signed_state", err)
	}
	both, bothOpen := call, open
	both.SealTo, both.Clear = w.key(), true
	bothOpen.SealTo, bothOpen.Clear = w.key(), true
	if _, err := w.caller.Call(ctx, both); !errors.Is(err, stationlink.ErrSealedAndClear) {
		t.Errorf("a call stating both: %v, want ErrSealedAndClear", err)
	}
	if _, err := w.caller.OpenStream(ctx, bothOpen); !errors.Is(err, stationlink.ErrSealedAndClear) {
		t.Errorf("an open stating both: %v, want ErrSealedAndClear", err)
	}
	if n := entered.Load(); n != 0 {
		t.Fatalf("a refused call or open reached the provider %d times", n)
	}

	call.Clear, open.Clear = true, true
	if got, err := w.caller.Call(ctx, call); err != nil || text(got) != "x" {
		t.Errorf("a clear call: %v, %v", got, err)
	}
	stream, err := w.caller.OpenStream(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	if event, err := stream.Recv(ctx); err != nil || text(event.Payload) != "watched" {
		t.Errorf("a clear stream: %+v, %v", event, err)
	}
}

func text(v cbor.Value) string {
	s, _ := v.AsText()
	return s
}
