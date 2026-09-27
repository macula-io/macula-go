package stationlink_test

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// Sealed calls and streams end to end (macula 13, E2E design §5): a Go caller
// sealing to the key a Go provider names, over a test station that routes
// what it cannot read.

// clock is a keyring's clock a test moves.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type sealedWorld struct {
	realm    teststation.Realm
	provider *stationlink.Link
	caller   *stationlink.Link
	ring     *seal.Keyring
	clock    *clock
}

func newSealedWorld(t *testing.T, p profile.Profile, name string) sealedWorld {
	t.Helper()
	s := teststation.Start(t, p, name)
	realm := teststation.NewRealm(t, p, "sealed.test", "mcl-vault")
	c := &clock{now: time.Now()}
	ring, err := seal.NewKeyring(p, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	provider := dialConfigured(t, s, p, name+" provider", func(cfg *stationlink.Config) { cfg.Keyring, cfg.KEMAdvertise = ring, true })
	realm.Admit(t, s, provider.NodeID())
	return sealedWorld{realm: realm, provider: provider, caller: dialIn(t, s, p, name+" caller"), ring: ring, clock: c}
}

// dialConfigured is dialIn with the Config shaped first.
func dialConfigured(t *testing.T, s *teststation.Station, p profile.Profile, name string, shape func(*stationlink.Config)) *stationlink.Link {
	t.Helper()
	key := teststation.Key(t, p, name)
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	cfg := stationlink.Config{Target: s.Target(), IdentityKey: key, Issuer: issuer}
	shape(&cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := stationlink.Dial(ctx, cfg)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = link.Close("test_done") })
	s.WaitAccepted()
	return link
}

func (w sealedWorld) key() []byte { return w.ring.Current().PublicKey().Carried() }

func (w sealedWorld) serve(t *testing.T, o stationlink.Offer) {
	t.Helper()
	o.Realm, o.RealmKey = w.realm.ID, w.realm.RealmKey()
	if _, err := w.provider.Serve(t.Context(), o); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestASealedCallEndToEnd(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			w := newSealedWorld(t, p, "sealed call")
			var sealed bool
			w.serve(t, stationlink.Offer{Procedure: "mcl-vault/open", Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
				sealed = r.Sealed
				return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("got"), Val: r.Payload}}), nil
			}})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			got, err := w.caller.Call(ctx, stationlink.Call{Realm: w.realm.ID, Procedure: "mcl-vault/open", Target: w.provider.NodeID(),
				Payload: cbor.Text("the secret"), Timeout: 5 * time.Second, SealTo: w.key()})
			if err != nil {
				t.Fatalf("Call: %v", err)
			}
			echoed, _ := got.Get("got")
			if text, _ := echoed.AsText(); text != "the secret" || !sealed {
				t.Errorf("got %v, the handler saw it sealed: %v", got, sealed)
			}
		})
	}
}

// Every stream mode seals both ways: raw and structured chunks, a reply, and
// what the provider receives from the caller.
func TestSealedStreamsEndToEnd(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			w := newSealedWorld(t, p, "sealed streams")
			w.serve(t, stationlink.Offer{Procedure: "mcl-vault/watch", Stream: &stationlink.StreamOffer{Mode: frame.Bidi,
				Handler: func(ctx context.Context, s *stationlink.Stream) error {
					if text, _ := s.Request().Payload.AsText(); text != "open sesame" {
						return errors.New("the open's payload did not open")
					}
					event, err := s.Recv(ctx)
					if err != nil {
						return err
					}
					body, _ := event.Body.AsBytes()
					if err := s.Send(append([]byte("echo "), body...)); err != nil {
						return err
					}
					if err := s.SendValue(cbor.Map([]cbor.MapEntry{{Key: cbor.Text("n"), Val: cbor.Uint64(7)}})); err != nil {
						return err
					}
					return s.Reply(cbor.Text("done"))
				}}})
			stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/watch",
				Target: w.provider.NodeID(), Mode: frame.Bidi, Payload: cbor.Text("open sesame"), SealTo: w.key()})
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			if err := stream.Send([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"echo hello", "n=7", "reply done"} {
				event, err := recv(t, stream)
				if err != nil {
					t.Fatalf("%s: %v", want, err)
				}
				switch want {
				case "echo hello":
					if body, _ := event.Body.AsBytes(); string(body) != want {
						t.Errorf("the raw chunk: %q", body)
					}
				case "n=7":
					n, _ := event.Body.Get("n")
					if v, _ := n.AsInt64(); v != 7 {
						t.Errorf("the structured chunk: %v", event.Body)
					}
				case "reply done":
					if text, _ := event.Payload.AsText(); event.Kind != stationlink.StreamReply || text != "done" {
						t.Errorf("the reply: %+v", event)
					}
				}
			}
		})
	}
}

// A sealed stream refused sealed_refused before it has sent anything reseals
// once to the key the provider names, and keeps its session; without a
// reseal, the refusal ends it naming that key.
func TestASealedStreamResealsOnceWhenRefused(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "reseal")
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error { return s.Reply(cbor.Text("counted")) }}})
	stale := must[*seal.PrivateKey](t)(seal.GenerateKey(profile.PQPure)).PublicKey().Carried()
	current := w.ring.CurrentID()
	var named *[seal.KeyIDSize]byte
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: stale,
		Reseal: func(id *[seal.KeyIDSize]byte) ([]byte, error) { named = id; return w.key(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	// The application may read the stream's request while it reseals.
	answered, reading := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(reading)
		for {
			select {
			case <-answered:
				return
			default:
				_ = stream.Request()
			}
		}
	}()
	event, err := recv(t, stream)
	close(answered)
	<-reading
	if text, _ := event.Payload.AsText(); err != nil || text != "counted" {
		t.Fatalf("the resealed stream: %+v, %v", event, err)
	}
	if named == nil || *named != current {
		t.Errorf("the reseal was given %v, the provider holds %x", named, current)
	}

	refused, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: stale})
	if err != nil {
		t.Fatal(err)
	}
	var streamErr *stationlink.StreamError
	if _, err := recv(t, refused); !errors.As(err, &streamErr) || streamErr.Code != "sealed_refused" ||
		streamErr.Message != hex.EncodeToString(current[:]) {
		t.Errorf("without a reseal: %v", err)
	}
}

// A resealed stream keeps the deadline it was opened with, as macula's
// reopened_client_stream/5 keeps it: resealing does not extend its life.
func TestAResealedStreamKeepsItsDeadline(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "reseal deadline")
	seen := make(chan uint64, 1)
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error {
			seen <- s.Request().Deadline
			return s.Reply(cbor.Text("counted"))
		}}})
	stale := must[*seal.PrivateKey](t)(seal.GenerateKey(profile.PQPure)).PublicKey().Carried()
	const deadline = 10 * time.Second
	before := time.Now()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: stale, Deadline: deadline,
		Reseal: func(*[seal.KeyIDSize]byte) ([]byte, error) {
			time.Sleep(1500 * time.Millisecond)
			return w.key(), nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv(t, stream); err != nil {
		t.Fatal(err)
	}
	if got, latest := <-seen, uint64(before.Add(deadline+500*time.Millisecond).UnixMilli()); got > latest {
		t.Errorf("the resealed open's deadline is %d ms past the first open's latest", got-latest)
	}
}

// A required stream refuses a clear open; a sealed stream keeps sealing and
// opening while its provider's key rotates out and is forgotten.
func TestASealedStreamOutlivesItsKey(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "rotation")
	proceed := make(chan struct{})
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/long", Confidential: stationlink.ConfidentialRequired,
		Stream: &stationlink.StreamOffer{Mode: frame.Bidi, Handler: func(ctx context.Context, s *stationlink.Stream) error {
			if err := s.Send([]byte("before")); err != nil {
				return err
			}
			<-proceed
			event, err := s.Recv(ctx)
			if err != nil {
				return err
			}
			body, _ := event.Body.AsBytes()
			return s.Send(append([]byte("after "), body...))
		}}})
	clear, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/long",
		Target: w.provider.NodeID(), Mode: frame.Bidi, Payload: cbor.Map(nil), Clear: true})
	if err != nil {
		t.Fatal(err)
	}
	var streamErr *stationlink.StreamError
	if _, err := recv(t, clear); !errors.As(err, &streamErr) || streamErr.Code != "sealed_required" {
		t.Errorf("a clear open to a required stream: %v", err)
	}

	first := w.ring.CurrentID()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/long",
		Target: w.provider.NodeID(), Mode: frame.Bidi, Payload: cbor.Map(nil), SealTo: w.key()})
	if err != nil {
		t.Fatal(err)
	}
	if event, err := recv(t, stream); err != nil || string(must[[]byte](t)(bytesOf(event.Body))) != "before" {
		t.Fatalf("before the rotation: %+v, %v", event, err)
	}
	// The key rotates at its first use past its lifetime (an advertisement
	// renewal reads it every few minutes), and is forgotten 30 minutes on.
	w.clock.advance(seal.KeyLifetime)
	if w.ring.CurrentID() == first {
		t.Fatal("the stream's key did not rotate")
	}
	w.clock.advance(seal.RetiredKeyKept + time.Minute)
	if _, held := w.ring.Find(first); held {
		t.Fatal("the stream's key was not forgotten")
	}
	close(proceed)
	if err := stream.Send([]byte("rotation")); err != nil {
		t.Fatal(err)
	}
	if event, err := recv(t, stream); err != nil || string(must[[]byte](t)(bytesOf(event.Body))) != "after rotation" {
		t.Fatalf("after the rotation: %+v, %v", event, err)
	}
	if _, err := recv(t, stream); err != nil && !errors.Is(err, io.EOF) {
		var ended *stationlink.StreamError
		if !errors.As(err, &ended) {
			t.Errorf("the stream's end: %v", err)
		}
	}
}

func bytesOf(v cbor.Value) ([]byte, error) {
	b, ok := v.AsBytes()
	if !ok {
		return nil, errors.New("not a byte string")
	}
	return b, nil
}

func must[T any](t *testing.T) func(T, error) T {
	return func(v T, err error) T {
		t.Helper()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		return v
	}
}
