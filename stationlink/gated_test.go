package stationlink_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
)

const (
	gatedRealm  = "gated.test"
	gatedCall   = "mcl-tube/count"
	gatedStream = "mcl-tube/watch"
)

// gatedWorld is one station, a realm whose name is canonical so a UCAN can
// grant in it, a provider serving a gated procedure, a caller, and the
// issuer a ucan_required policy names.
type gatedWorld struct {
	profile  profile.Profile
	realm    teststation.Realm
	provider *stationlink.Link
	caller   *stationlink.Link
	root     *identity.NodeKey
}

func newGatedWorld(t *testing.T, p profile.Profile, name string) gatedWorld {
	t.Helper()
	s := teststation.Start(t, p, name)
	realm := teststation.NewRealm(t, p, gatedRealm, "mcl-tube")
	provider := dialIn(t, s, p, name+" provider")
	realm.Admit(t, s, provider.NodeID())
	return gatedWorld{profile: p, realm: realm, provider: provider, caller: dialIn(t, s, p, name+" caller"),
		root: teststation.Key(t, p, name+" root")}
}

func (w gatedWorld) rootPolicy(t *testing.T) ucan.Policy {
	t.Helper()
	id, err := w.root.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	return ucan.UCANRequired{Issuer: id}
}

func (w gatedWorld) serveCall(t *testing.T, policy ucan.Policy) {
	t.Helper()
	_, err := w.provider.Serve(t.Context(), stationlink.Offer{Realm: w.realm.ID, Procedure: gatedCall,
		Handler:  func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil },
		RealmKey: w.realm.RealmKey(), Policy: policy})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

func (w gatedWorld) serveStream(t *testing.T, policy ucan.Policy) {
	t.Helper()
	_, err := w.provider.Serve(t.Context(), stationlink.Offer{Realm: w.realm.ID, Procedure: gatedStream,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			return s.Send([]byte("granted"))
		}}, RealmKey: w.realm.RealmKey(), Policy: policy})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// token is issuer's UCAN to audience granting can on with, living a minute,
// naming prf as its chain's parent.
func token(t *testing.T, issuer *identity.NodeKey, audience [32]byte, with, can string, prf ...string) []byte {
	t.Helper()
	tok, err := ucan.Create(issuer, audience, []ucan.Capability{{With: with, Can: can}},
		ucan.Options{Exp: time.Now().Unix() + 60, Prf: prf})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return tok
}

func nodeID(t *testing.T, k *identity.NodeKey) [32]byte {
	t.Helper()
	id, err := k.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (w gatedWorld) call(t *testing.T, tok []byte, proofs ...[]byte) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := w.caller.Call(ctx, stationlink.Call{Realm: w.realm.ID, Procedure: gatedCall, Target: w.provider.NodeID(),
		Payload: cbor.Text("hello"), Timeout: 5 * time.Second, Token: tok, Proofs: proofs})
	return err
}

func (w gatedWorld) open(t *testing.T, tok []byte, proofs ...[]byte) error {
	t.Helper()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: gatedStream,
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), Token: tok, Proofs: proofs})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	event, err := recv(t, stream)
	if err != nil {
		return err
	}
	if body, _ := event.Body.AsBytes(); event.Kind != stationlink.StreamData || string(body) != "granted" {
		t.Errorf("the served stream sent %+v", event)
	}
	return nil
}

// refusal is the code a provider refused a CALL or a STREAM_OPEN with, or ""
// when it served it; any other failure fails the test.
func refusal(t *testing.T, err error) string {
	t.Helper()
	var provider *stationlink.ProviderError
	var stream *stationlink.StreamError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &provider):
		return provider.Code
	case errors.As(err, &stream) && !stream.Relay:
		return stream.Code
	}
	t.Fatalf("neither served nor refused by the provider: %v", err)
	return ""
}

// gatedCase is a token and the proofs presented with it, and the provider's
// answer: "" to serve it, else the code it refuses with.
type gatedCase struct {
	token  []byte
	proofs [][]byte
	want   string
}

// cases are the presentations a procedure gated on w's root must judge as
// macula's link does: a root token and a delegated chain served; no token,
// another issuer, another procedure, a token for another node, and a chain
// without its proof unauthorized; a proof no token names malformed_frame.
func (w gatedWorld) cases(t *testing.T, procedure string) map[string]gatedCase {
	t.Helper()
	org := "mri:org:" + gatedRealm + "/mcl-tube"
	caller := w.caller.NodeID()
	alice := teststation.Key(t, w.profile, "gated alice")
	other := teststation.Key(t, w.profile, "gated other")
	direct := token(t, w.root, caller, org, "invoke")
	toAlice := token(t, w.root, nodeID(t, alice), org, "invoke")
	chained := token(t, alice, caller, "mri:proc:"+gatedRealm+"/"+procedure, "invoke", ucan.ProofID(toAlice))
	return map[string]gatedCase{
		"a root token":          {direct, nil, ""},
		"a delegated chain":     {chained, [][]byte{toAlice}, ""},
		"no token":              {nil, nil, "unauthorized"},
		"another issuer":        {token(t, other, caller, org, "invoke"), nil, "unauthorized"},
		"another procedure":     {token(t, w.root, caller, "mri:proc:"+gatedRealm+"/mcl-tube/other", "invoke"), nil, "unauthorized"},
		"another node's token":  {toAlice, nil, "unauthorized"},
		"a chain without proof": {chained, nil, "unauthorized"},
		"an unreferenced proof": {direct, [][]byte{toAlice}, "malformed_frame"},
	}
}

// A procedure gated on an issuer authorizes each CALL as macula's link does.
func TestAGatedProcedureAuthorizesEachCall(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			w := newGatedWorld(t, p, "gated call")
			w.serveCall(t, w.rootPolicy(t))
			for name, c := range w.cases(t, gatedCall) {
				if got := refusal(t, w.call(t, c.token, c.proofs...)); got != c.want {
					t.Errorf("%s: %q, want %q", name, got, c.want)
				}
			}
		})
	}
}

// A streaming procedure gated on an issuer authorizes each STREAM_OPEN as
// macula's link does, refusing one on its own stream.
func TestAGatedStreamAuthorizesEachOpen(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			w := newGatedWorld(t, p, "gated stream")
			w.serveStream(t, w.rootPolicy(t))
			for name, c := range w.cases(t, gatedStream) {
				if got := refusal(t, w.open(t, c.token, c.proofs...)); got != c.want {
					t.Errorf("%s: %q, want %q", name, got, c.want)
				}
			}
		})
	}
}

// A procedure gated on realm membership serves a token the realm key granted
// with the can it names, and refuses one with another can.
func TestARealmMemberProcedureNeedsTheRealmsGrant(t *testing.T) {
	w := newGatedWorld(t, profile.PQPure, "realm member")
	keyID := identity.KeyIDOf(w.realm.RealmKey(), profile.PQPure)
	w.serveCall(t, ucan.RealmMemberRequired{KeyID: keyID, Can: "count"})
	grant := "mri:realm:" + gatedRealm
	if got := refusal(t, w.call(t, token(t, w.realm.Key, w.caller.NodeID(), grant, "count"))); got != "" {
		t.Errorf("the realm's grant: refused %q", got)
	}
	if got := refusal(t, w.call(t, token(t, w.realm.Key, w.caller.NodeID(), grant, "invoke"))); got != "unauthorized" {
		t.Errorf("another can: %q, want unauthorized", got)
	}
}

// An open procedure serves any caller and ignores a token it is sent, even
// one no verifier would accept.
func TestAnOpenProcedureIgnoresAnyToken(t *testing.T) {
	w := newGatedWorld(t, profile.PQPure, "open")
	w.serveCall(t, nil)
	if got := refusal(t, w.call(t, []byte("not a token"), []byte("not a proof"))); got != "" {
		t.Errorf("refused %q", got)
	}
}

// Serving refuses a realm member policy that names no can, as macula's
// advertise does.
func TestServeRefusesARealmMemberPolicyWithoutACan(t *testing.T) {
	w := newGatedWorld(t, profile.PQPure, "no can")
	_, err := w.provider.Serve(t.Context(), stationlink.Offer{Realm: w.realm.ID, Procedure: gatedCall,
		Handler:  func(context.Context, stationlink.Request) (cbor.Value, error) { return cbor.Map(nil), nil },
		RealmKey: w.realm.RealmKey(), Policy: ucan.RealmMemberRequired{KeyID: [32]byte{1}}})
	if !errors.Is(err, stationlink.ErrInvalidOffer) {
		t.Errorf("%v, want ErrInvalidOffer", err)
	}
}
