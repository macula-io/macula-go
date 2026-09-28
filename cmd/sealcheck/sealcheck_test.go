package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// A world like M4's: on one test station, an echo_sealed provider (its key
// advertised when keyed, both procedures confidential "required" then), a plain
// echo provider for the clear leg, and the seed and realm a caller outside the
// fleet is given.
func world(t *testing.T, keyed bool) config {
	t.Helper()
	s := teststation.Start(t, profile.PQPure, "sealcheck")
	realm := teststation.NewRealm(t, profile.PQPure, "sealcheck", "mcl-echo")
	sealedKey := teststation.Key(t, profile.PQPure, "echo_sealed")
	plainKey := teststation.Key(t, profile.PQPure, "echo")
	sealedID, _ := sealedKey.NodeID()
	plainID, _ := plainKey.NodeID()
	realm.Admit(t, s, sealedID, plainID)
	seed := pool.Seed{Host: s.Host, Port: s.Port, NodeID: s.NodeID}
	join := func(key *identity.NodeKey, kem bool) *pool.Pool {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		p, err := pool.Connect(ctx, []pool.Seed{seed}, pool.Opts{IdentityKey: key,
			RealmTrust: map[[32]byte][]byte{realm.ID: realm.RealmKey()}, KEMAdvertise: kem})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = p.Close() })
		return p
	}
	echo := func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }
	conf := stationlink.ConfidentialPreferred
	if keyed {
		conf = stationlink.ConfidentialRequired
	}
	sealed := join(sealedKey, keyed)
	serve := func(p *pool.Pool, o pool.Offer) {
		if _, err := p.Serve(t.Context(), o); err != nil {
			t.Fatal(err)
		}
	}
	serve(sealed, pool.Offer{Realm: realm.ID, Procedure: "mcl-echo/echo_sealed", Handler: echo, Confidential: conf})
	serve(sealed, pool.Offer{Realm: realm.ID, Procedure: "mcl-echo/echo_sealed_stream", Confidential: conf,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, st *stationlink.Stream) error {
			if err := st.Send([]byte("echo")); err != nil {
				return err
			}
			return st.Reply(cbor.Text("streamed"))
		}}})
	serve(join(plainKey, false), pool.Offer{Realm: realm.ID, Procedure: "mcl-echo/echo", Handler: echo})
	return config{Seeds: []pool.Seed{seed}, Profile: profile.PQPure, Realm: realm.ID, RealmKey: realm.RealmKey(),
		Sealed: "mcl-echo/echo_sealed", Clear: "mcl-echo/echo", StreamProcedure: "mcl-echo/echo_sealed_stream",
		N: 3, Chunks: 2, Call: true, Stream: true, Timeout: 20 * time.Second}
}

// Against a provider that advertises its key, every report says sealed, to that
// key, and the measurement passes and records the overhead.
func TestSealcheckPassesAgainstAKeyedProvider(t *testing.T) {
	cfg := world(t, true)
	var out bytes.Buffer
	if err := measure(t.Context(), cfg, &out); err != nil {
		t.Fatalf("measure: %v\n%s", err, out.String())
	}
	log := out.String()
	for _, want := range []string{"macula_go:", "call 1 sealed=1", "stream sealed=1", "clear 1", "overhead", "overall: PASS"} {
		if !strings.Contains(log, want) {
			t.Errorf("the log has no %q:\n%s", want, log)
		}
	}
}

// Against a provider that advertises no key, the check fails: a required call
// to it is refused, so nothing sealed is reported and the run is FAIL.
func TestSealcheckFailsAgainstAProviderWithNoKey(t *testing.T) {
	cfg := world(t, false)
	var out bytes.Buffer
	if err := measure(t.Context(), cfg, &out); err == nil {
		t.Fatalf("measure passed against a keyless provider:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "overall: FAIL") {
		t.Errorf("the log does not say FAIL:\n%s", out.String())
	}
}
