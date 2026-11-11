package stationlink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
)

// The link is not a way round the pool: a serve with no policy is refused here
// too, before the advertisement is built, unary and streaming alike
// (macula-go#57, #60).
func TestALinkServeWithNoPolicyIsRefused(t *testing.T) {
	w := newGatedWorld(t, profile.PQPure, "link no policy")
	handler := func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }
	for _, c := range []struct {
		name  string
		offer stationlink.Offer
	}{
		{"unary", stationlink.Offer{Realm: w.realm.ID, Procedure: gatedCall, Handler: handler,
			RealmKey: w.realm.RealmKey()}},
		{"stream", stationlink.Offer{Realm: w.realm.ID, Procedure: gatedStream,
			Stream: &stationlink.StreamOffer{Mode: 0, Handler: func(_ context.Context, s *stationlink.Stream) error {
				return s.Close()
			}}, RealmKey: w.realm.RealmKey()}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := w.provider.Serve(t.Context(), c.offer); !errors.Is(err, stationlink.ErrPolicyRequired) {
				t.Errorf("Serve with no policy: %v, want ErrPolicyRequired", err)
			}
		})
	}
}
