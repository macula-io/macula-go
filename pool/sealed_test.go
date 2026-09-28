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
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// A pool's calls and streams seal to the key the provider's verified
// advertisement names (macula 13's E2E design §8.1): whenever it names one
// under ConfidentialPreferred, the default; never to a keyless one under
// ConfidentialRequired; never under ConfidentialOff. A provider pool with
// KEMAdvertise names its key.

type sealedPools struct {
	realm            teststation.Realm
	provider, caller *Pool
	station          *teststation.Station
}

func newSealedPools(t *testing.T, name string, kemAdvertise bool) sealedPools {
	t.Helper()
	s := teststation.Start(t, profile.PQPure, name)
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-pools", org)
	realm.Admit(t, s, nodeIDOf(t, name+" provider"))
	provider := connectWith(t, name+" provider", realm, func(o *Opts) { o.KEMAdvertise = kemAdvertise }, s)
	return sealedPools{realm: realm, provider: provider, caller: connect(t, name+" caller", realm, s), station: s}
}

func (w sealedPools) serve(t *testing.T, o Offer, seen *bool) {
	t.Helper()
	o.Realm = w.realm.ID
	if o.Handler == nil && o.Stream == nil {
		o.Handler = func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			*seen = r.Sealed
			return r.Payload, nil
		}
	}
	if _, err := w.provider.Serve(t.Context(), o); err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func TestAPoolSealsToAKeyedProvider(t *testing.T) {
	w := newSealedPools(t, "sealed pool", true)
	var sealed bool
	w.serve(t, Offer{Procedure: procedure}, &sealed)
	got, err := w.caller.Call(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("secret")})
	if text, _ := got.AsText(); err != nil || text != "secret" || !sealed {
		t.Fatalf("a preferred call: %q, %v, sealed %v", text, err, sealed)
	}
	// Only an advertisement naming no key is called in the clear (design
	// §8.1): off exists on an explicit target only, never at the pool, where
	// it is refused rather than ignored.
	if _, err := w.caller.Call(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Confidential: stationlink.ConfidentialOff}); !errors.Is(err, ErrConfidentialOff) {
		t.Errorf("an off call at the pool: %v, want ErrConfidentialOff", err)
	}
	if _, err := w.caller.OpenStream(t.Context(), StreamCall{Realm: w.realm.ID, Procedure: procedure, Mode: frame.ServerStream,
		Payload: cbor.Map(nil), Confidential: stationlink.ConfidentialOff}); !errors.Is(err, ErrConfidentialOff) {
		t.Errorf("an off stream at the pool: %v, want ErrConfidentialOff", err)
	}

	w.serve(t, Offer{Procedure: "mcl-echo/stream", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error {
			if s.Request().Sealed == nil {
				return errors.New("the open came clear")
			}
			return s.Reply(cbor.Text("streamed"))
		}}}, nil)
	stream, err := w.caller.OpenStream(t.Context(), StreamCall{Realm: w.realm.ID, Procedure: "mcl-echo/stream",
		Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	event, err := stream.Recv(ctx)
	if text, _ := event.Payload.AsText(); err != nil || text != "streamed" {
		t.Errorf("a sealed stream: %+v, %v", event, err)
	}
}

func TestARequiredCallRefusesAKeylessProvider(t *testing.T) {
	w := newSealedPools(t, "keyless", false)
	var sealed bool
	w.serve(t, Offer{Procedure: procedure}, &sealed)
	_, err := w.caller.Call(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Confidential: stationlink.ConfidentialRequired})
	var refused *stationlink.ConfidentialityError
	if !errors.As(err, &refused) || refused.Reason != stationlink.ReasonNoKEMKey {
		t.Errorf("%v, want no_kem_key", err)
	}
	if _, err := w.caller.Call(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("x")}); err != nil || sealed {
		t.Errorf("a preferred call to a keyless provider: %v, sealed %v", err, sealed)
	}
	if _, err := w.provider.Serve(t.Context(), Offer{Realm: w.realm.ID, Procedure: "mcl-echo/required",
		Handler:      func(context.Context, stationlink.Request) (cbor.Value, error) { return cbor.Map(nil), nil },
		Confidential: stationlink.ConfidentialRequired}); !errors.Is(err, stationlink.ErrKEMAdvertiseDisabled) {
		t.Errorf("a required offer without kem_advertise: %v", err)
	}
}

// A call sealed to one candidate is never sent in the clear to another: once
// the sealed CALL went out, it has the whole deadline and its answer is the
// call's, even from a handler slower than the candidate's share, so a keyless
// next candidate never takes the payload in the clear.
func TestASealedCallNeverWalksToAKeylessCandidate(t *testing.T) {
	s, other := teststation.Start(t, profile.PQPure, "no walk"), teststation.Start(t, profile.PQPure, "no walk other")
	teststation.ShareDHT(s, other)
	realm := teststation.NewRealm(t, profile.PQPure, "no-walk", org)
	realm.Admit(t, s, nodeIDOf(t, "no walk provider"))
	realm.Admit(t, other, nodeIDOf(t, "no walk keyless"))
	w := sealedPools{realm: realm, station: s, caller: connect(t, "no walk caller", realm, s),
		provider: connectWith(t, "no walk provider", realm, func(o *Opts) { o.KEMAdvertise = true }, s)}
	keyless := connect(t, "no walk keyless", realm, other)
	var clearEntered atomic.Int32
	if _, err := keyless.Serve(t.Context(), Offer{Realm: w.realm.ID, Procedure: procedure,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			clearEntered.Add(1)
			return r.Payload, nil
		}}); err != nil {
		t.Fatal(err)
	}
	// The keyed provider advertises last, so it is the freshest candidate
	// and is tried first; its handler outlives its share.
	time.Sleep(50 * time.Millisecond)
	if _, err := w.provider.Serve(t.Context(), Offer{Realm: w.realm.ID, Procedure: procedure,
		Handler: func(ctx context.Context, r stationlink.Request) (cbor.Value, error) {
			time.Sleep(2500 * time.Millisecond)
			return r.Payload, nil
		}}); err != nil {
		t.Fatal(err)
	}
	// Both advertisements reach the DHT in their own time.
	for range 50 {
		if found, err := w.caller.Providers(t.Context(), w.realm.ID, procedure); err == nil && len(found) == 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	found, err := w.caller.Providers(t.Context(), w.realm.ID, procedure)
	if err != nil || len(found) != 2 || found[0].Node != w.provider.NodeID() {
		t.Fatalf("the candidates: %+v, %v", found, err)
	}
	result, err := w.caller.Call(t.Context(), Call{Realm: w.realm.ID, Procedure: procedure, Payload: cbor.Text("secret"),
		Timeout: 4 * time.Second})
	if text, _ := result.AsText(); err != nil || text != "secret" {
		t.Errorf("Call: %q, %v, want the keyed provider's answer", text, err)
	}
	if n := clearEntered.Load(); n != 0 {
		t.Errorf("the sealed payload reached the keyless provider in the clear %d times", n)
	}
}

// A reseal whose lookup fails fails closed, as macula's providers_ads/5
// reads a failed lookup as none: no_kem_key, which ends the call.
func TestAResealWhoseLookupFailsIsNoKEMKey(t *testing.T) {
	w := newSealedPools(t, "reseal lookup", true)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	named := [seal.KeyIDSize]byte{1}
	_, err := w.caller.resealed(ctx, resolvedKey{w.realm.ID, procedure, w.provider.NodeID()}, w.provider.NodeID(), &named)
	var refused *stationlink.ConfidentialityError
	if !errors.As(err, &refused) || refused.Reason != stationlink.ReasonNoKEMKey {
		t.Errorf("%v, want no_kem_key", err)
	}
}

// Content stays in the clear (macula 13, design §5.3): a keyed pool still
// shares and a caller still fetches.
func TestContentStaysClearUnderKEMAdvertise(t *testing.T) {
	w := newSealedPools(t, "content", true)
	mcid, err := w.provider.ShareContent(t.Context(), w.realm.ID, []byte("public by design"), "note")
	if err != nil {
		t.Fatal(err)
	}
	got, err := w.caller.GetContent(t.Context(), w.realm.ID, mcid, ContentOptions{})
	if err != nil || string(got) != "public by design" {
		t.Errorf("fetched %q, %v", got, err)
	}
	// Past the keyless window a keyed advertisement would refuse the clear
	// fetch, so the content procedure's advertisement names no key at all.
	content := record.OwnProcedure(w.provider.NodeID(), ContentProcedureName)
	found, err := w.caller.resolve(t.Context(), resolvedKey{w.realm.ID, content, w.provider.NodeID()}, nil)
	if err != nil || len(found) == 0 {
		t.Fatalf("the content advertisement: %v", err)
	}
	for _, c := range found {
		if c.kemKey != nil {
			t.Error("the content procedure's advertisement names a KEM key")
		}
	}
}

// A call that could not be kept confidential ends there, whatever the reason:
// the next candidate might be keyless, and a call sealed once is never sent
// in the clear (macula 13's failure_scope/1: request, not candidate).
func TestEveryConfidentialityFailureEndsTheCall(t *testing.T) {
	for _, reason := range []string{stationlink.ReasonNoKEMKey, stationlink.ReasonKeyMismatch,
		stationlink.ReasonReplyNotOpened, stationlink.ReasonNoSignedState} {
		if !answeredConfidentially(&stationlink.ConfidentialityError{Reason: reason}) {
			t.Errorf("%s moves the call to the next candidate", reason)
		}
	}
	if !answeredConfidentially(&stationlink.SealedRefusedError{}) || !answeredConfidentially(stationlink.ErrClearAnswerToSealed) {
		t.Error("a refused or clear answer to a sealed call moves it on")
	}
	if answeredConfidentially(stationlink.ErrCallTimeout) {
		t.Error("a timeout counted as a confidentiality answer")
	}
}

// After a sealed_refused, one fresh lookup decides: the provider's
// advertisement must name exactly the key its refusal named.
func TestAResealIsBoundToTheNamedKey(t *testing.T) {
	key := func() []byte {
		k, err := seal.GenerateKey(profile.PQPure)
		if err != nil {
			t.Fatal(err)
		}
		return k.PublicKey().Carried()
	}
	current, other := key(), key()
	currentID, otherID := seal.KeyID(current), seal.KeyID(other)
	node := [32]byte{7}
	keyed := func(n [32]byte, k []byte) candidate {
		c := candidate{Provider: Provider{Node: n}, kemKey: k}
		if k != nil {
			c.kemKeyID = seal.KeyID(k)
		}
		return c
	}
	for _, c := range []struct {
		name   string
		named  *[seal.KeyIDSize]byte
		fresh  []candidate
		want   []byte
		reason string
	}{
		{"the named key", &currentID, []candidate{keyed(node, current)}, current, ""},
		{"another key advertised", &currentID, []candidate{keyed(node, other)}, nil, stationlink.ReasonKeyMismatch},
		{"no key advertised", &currentID, []candidate{keyed(node, nil)}, nil, stationlink.ReasonNoKEMKey},
		{"no advertisement", &currentID, nil, nil, stationlink.ReasonNoKEMKey},
		{"a stale advertisement before the named one", &currentID, []candidate{keyed(node, other), keyed(node, current)}, current, ""},
		{"a keyless advertisement before the named one", &currentID, []candidate{keyed(node, nil), keyed(node, current)}, current, ""},
		{"the provider holds none: its first key", nil, []candidate{keyed(node, nil), keyed(node, current)}, current, ""},
		{"the provider holds none and names none", nil, []candidate{keyed(node, nil)}, nil, stationlink.ReasonNoKEMKey},
		{"another provider's advertisement", &otherID, []candidate{keyed([32]byte{8}, other)}, nil, stationlink.ReasonNoKEMKey},
		{"another provider's key, the provider holding none", nil, []candidate{keyed([32]byte{8}, other)}, nil, stationlink.ReasonNoKEMKey},
	} {
		got, err := resealKey(node, c.named, c.fresh)
		var refused *stationlink.ConfidentialityError
		switch {
		case c.reason == "" && (err != nil || string(got) != string(c.want)):
			t.Errorf("%s: %v", c.name, err)
		case c.reason != "" && (!errors.As(err, &refused) || refused.Reason != c.reason):
			t.Errorf("%s: %v, want %s", c.name, err, c.reason)
		}
	}
}
