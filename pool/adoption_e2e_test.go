package pool

import (
	"context"
	"errors"
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

// A pool adopts the key a keyed provider's signed refusal carries, and uses it
// (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3, release A0): the next call, and
// the next open, to that provider go out sealed at once, so the provider is
// asked in the clear once and never again.
//
// The provider here is a station link built to carry the key in a
// sealed_required refusal, release A's sending side, which is on in the test
// only (section 8.1): its advertisement names no key, as an A0 provider's does.

// adoptingProvider is that provider: a link with a keyring, KEMKeyInRefusal on,
// and no key in its advertisement.
type adoptingProvider struct {
	link *stationlink.Link
}

func newAdoptingProvider(t *testing.T, s *teststation.Station, realm teststation.Realm, name string,
	now func() time.Time) adoptingProvider {
	t.Helper()
	key := teststation.Key(t, profile.PQPure, name)
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ring, err := seal.NewKeyring(profile.PQPure, now)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := stationlink.Dial(ctx, stationlink.Config{Target: s.Target(), IdentityKey: key, Issuer: issuer,
		Keyring: ring, KEMKeyInRefusal: true})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = link.Close("test_done") })
	realm.Admit(t, s, link.NodeID())
	return adoptingProvider{link: link}
}

func (p adoptingProvider) serve(t *testing.T, realm teststation.Realm, o stationlink.Offer) {
	t.Helper()
	o.Realm, o.RealmKey = realm.ID, realm.RealmKey()
	if _, err := p.link.Serve(t.Context(), o); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// refused is how many of the provider's refusals of code it has sent.
func (p adoptingProvider) refused(code string) uint64 { return p.link.Unrouted()["call_refused_"+code] }

// declined is how many stream opens the provider refused with code.
func (p adoptingProvider) declined(code string) uint64 {
	return p.link.Unrouted()["stream_refused_"+code]
}

// A pool's second call to a provider whose key it adopted is sealed from the
// start: the provider refuses the clear call once, and never again.
func TestAPoolSealsTheCallItLearntTheKeyFrom(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "adopt pool calls")
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-pools", org)
	provider := newAdoptingProvider(t, s, realm, "adopt pool calls provider", time.Now)
	provider.serve(t, realm, stationlink.Offer{Procedure: procedure, Confidential: stationlink.ConfidentialRequired,
		Handler: echo})
	caller := connect(t, "adopt pool calls caller", realm, s)
	for round := 0; round < 2; round++ {
		got, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("secret")})
		if text, _ := got.AsText(); err != nil || text != "secret" {
			t.Fatalf("call %d: %q, %v", round+1, text, err)
		}
	}
	if n := provider.refused("sealed_required"); n != 1 {
		t.Errorf("the provider refused %d clear calls, want 1: the second did not go out sealed", n)
	}
}

// The same for a stream: the pool's second open to that provider is sealed from
// the start, and its first one replayed.
func TestAPoolSealsTheOpenItLearntTheKeyFrom(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "adopt pool opens")
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-pools", org)
	provider := newAdoptingProvider(t, s, realm, "adopt pool opens provider", time.Now)
	provider.serve(t, realm, stationlink.Offer{Procedure: procedure, Confidential: stationlink.ConfidentialRequired,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
			Handler: func(_ context.Context, st *stationlink.Stream) error { return st.Reply(cbor.Text("opened")) }}})
	caller := connect(t, "adopt pool opens caller", realm, s)
	for round := 0; round < 2; round++ {
		if err := openedAndAnswered(caller, realm); err != nil {
			t.Fatalf("open %d: %v", round+1, err)
		}
	}
	if n := provider.declined("sealed_required"); n != 1 {
		t.Errorf("the provider refused %d clear opens, want 1: the second did not go out sealed", n)
	}
}

// openedAndAnswered opens a server stream and reads its reply.
func openedAndAnswered(caller *Pool, realm teststation.Realm) error {
	stream, err := caller.OpenStream(context.Background(), StreamCall{Realm: realm.ID, Procedure: procedure,
		Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		event, err := stream.Recv(ctx)
		if err != nil {
			return err
		}
		if event.Kind == stationlink.StreamReply {
			return nil
		}
	}
}

// A call the provider refuses sealed_refused after the adoption is resealed
// once under A1's rule, or ends as a confidentiality answer: never as a call
// that states both a key and the clear, which no send can be.
//
// The provider's clock rotates its keyring on every reading, so the key the
// refusal carried has been rotated out and forgotten by the time the caller
// seals to it: exactly the provider that lost its key between the two.
func TestAnAdoptedCallRefusedSealedRefusedIsNeverSealedAndClear(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "adopt a1")
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-pools", org)
	provider := newAdoptingProvider(t, s, realm, "adopt a1 provider", rotatingClock())
	provider.serve(t, realm, stationlink.Offer{Procedure: procedure, Confidential: stationlink.ConfidentialRequired,
		Handler: echo})
	caller := connect(t, "adopt a1 caller", realm, s)
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("secret")})
	if errors.Is(err, stationlink.ErrSealedAndClear) {
		t.Fatalf("the adopted call's A1 reseal stated both a key and the clear: %v", err)
	}
	// The advertisement names no key, so A1's fresh lookup finds none to seal
	// to: the call ends no_kem_key, as the design's precedence says.
	var refused *stationlink.ConfidentialityError
	if !errors.As(err, &refused) || refused.Reason != stationlink.ReasonNoKEMKey {
		t.Fatalf("the adopted call: %v, want no_kem_key", err)
	}
	if n := provider.refused("sealed_refused"); n != 1 {
		t.Errorf("the provider refused %d sealed calls, want 1: the call did not reseal to the key it adopted", n)
	}
}

// rotatingClock reads a time one key lifetime and one retirement apart on every
// call, so a keyring it drives rotates and forgets its keys between two
// readings.
func rotatingClock() func() time.Time {
	now := time.Now()
	return func() time.Time {
		at := now
		now = now.Add(seal.KeyLifetime + seal.RetiredKeyKept + time.Minute)
		return at
	}
}

// A key the pool learnt from a refusal is dropped when a later call is refused
// sealed_refused: that refusal is the provider's own and signed, so the key it
// beat is stale, and keeping it would seal every later call to a key the
// provider no longer opens, with no way back to the clear that learns the new
// one.
func TestAPoolForgetsAKeyTheProviderRefused(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "adopt rotated")
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-pools", org)
	clock := &switchableClock{now: time.Now()}
	provider := newAdoptingProvider(t, s, realm, "adopt rotated provider", clock.Now)
	provider.serve(t, realm, stationlink.Offer{Procedure: procedure, Confidential: stationlink.ConfidentialRequired,
		Handler: echo})
	caller := connect(t, "adopt rotated caller", realm, s)
	assertCallEchoes(t, caller, realm, "one")
	// The provider rotates its keys: the key the pool learnt is gone, while its
	// advertisement still names none.
	clock.jump()
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("two")})
	var refused *stationlink.ConfidentialityError
	if !errors.As(err, &refused) || refused.Reason != stationlink.ReasonNoKEMKey {
		t.Fatalf("the stale key's call: %v, want no_kem_key", err)
	}
	// Its key dropped, the next call goes clear again and learns the key the
	// provider holds now.
	clock.freeze()
	assertCallEchoes(t, caller, realm, "three")
	if n := provider.refused("sealed_required"); n != 2 {
		t.Errorf("the provider refused %d clear calls, want 2: the learnt key was not dropped", n)
	}
}

// assertCallEchoes calls the provider and checks the payload came back.
func assertCallEchoes(t *testing.T, caller *Pool, realm teststation.Realm, payload string) {
	t.Helper()
	got, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text(payload)})
	if text, _ := got.AsText(); err != nil || text != payload {
		t.Fatalf("the call %q: %q, %v", payload, text, err)
	}
}

// switchableClock reads a fixed time until it is switched into jumping, and
// then advances by a key lifetime and a retirement on every reading, so a
// keyring it drives rotates and forgets its keys between two of them.
type switchableClock struct {
	mu      sync.Mutex
	now     time.Time
	jumping bool
}

// Now reads the clock, advancing it first while it is jumping.
func (c *switchableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.jumping {
		c.now = c.now.Add(seal.KeyLifetime + seal.RetiredKeyKept + time.Minute)
	}
	return c.now
}

// jump sets the clock jumping: every later reading is a rotation and a
// retirement on from the one before.
func (c *switchableClock) jump() {
	c.mu.Lock()
	c.jumping = true
	c.mu.Unlock()
}

// freeze stops the clock jumping, keeping the time it reached.
func (c *switchableClock) freeze() {
	c.mu.Lock()
	c.jumping = false
	c.mu.Unlock()
}
