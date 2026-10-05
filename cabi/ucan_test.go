package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
)

func hexNode(t *testing.T, k *identity.NodeKey) string {
	t.Helper()
	id, err := k.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(id[:])
}

// A policy, a token's grants and options, and the proofs a call presents are
// checked as they cross, each malformed one refused invalid_argument.
func TestUCANArgumentsAreChecked(t *testing.T) {
	root := teststation.Key(t, profile.PQPure, "abi ucan root")
	id := hexNode(t, root)
	for _, policy := range []string{
		``, `{}`, `{"kind":"open"}`, `{"kind":"ucan_required"}`, `{"kind":"ucan_required","issuer":"00"}`,
		`{"kind":"ucan_required","issuer":"` + id + `","can":"invoke"}`,
		`{"kind":"realm_member_required","key_id":"` + id + `"}`,
		`{"kind":"realm_member_required","key_id":"` + id + `","can":"invoke","issuer":"` + id + `"}`,
		`{"kind":"ucan_required","issuer":"` + id + `","extra":1}`,
	} {
		if _, err := gatedPolicy(policy); kindOf(err) != kindInvalidArgument {
			t.Errorf("policy %s: %v, want invalid_argument", policy, err)
		}
	}
	if p, err := policyOf(`{"kind":"realm_member_required","key_id":"` + id + `","can":"invoke"}`); err != nil ||
		p != (ucan.RealmMemberRequired{KeyID: [32]byte(mustHex(t, id)), Can: "invoke"}) {
		t.Errorf("a realm member policy: %v, %v", p, err)
	}
	for _, c := range []struct{ caps, options string }{
		{`{"with":"mri:realm:io.macula","can":"invoke"}`, ``},
		{`[{"with":"mri:realm:io.macula","can":"invoke","extra":1}]`, ``},
		{`[{"with":"mri:realm:io.macula","can":"invoke"}]`, `{"prf":"not a list"}`},
		{`[{"with":"mri:realm:io.macula","can":"invoke"}]`, `{"exp":1}`},
	} {
		if _, err := ucanCreate(root, [32]byte{}, c.caps, time.Now().Unix()+60, c.options); kindOf(err) != kindInvalidArgument {
			t.Errorf("caps %s, options %s: %v, want invalid_argument", c.caps, c.options, err)
		}
	}
	caps := `[{"with":"mri:realm:io.macula","can":"invoke"}]`
	ms := time.Now().UnixMilli() + 3_600_000
	if _, err := ucanCreate(root, [32]byte{}, caps, ms, ``); kindOf(err) != kindInvalidArgument ||
		!strings.Contains(err.Error(), fmt.Sprintf("exp %d", ms)) {
		t.Errorf("an exp in milliseconds: %v, want invalid_argument", err)
	}
	nbf := time.Now().Unix() + 120
	if _, err := ucanCreate(root, [32]byte{}, caps, nbf-60, fmt.Sprintf(`{"nbf":%d}`, nbf)); kindOf(err) != kindInvalidArgument ||
		!strings.Contains(err.Error(), fmt.Sprintf("nbf %d, exp %d", nbf, nbf-60)) {
		t.Errorf("an nbf after its exp: %v, want invalid_argument", err)
	}
	if _, err := ucanCreate(root, [32]byte{}, caps, time.Now().Unix()+366*24*3600, ``); err != nil {
		t.Errorf("a token for a year: %v", err)
	}
	for _, proofs := range []string{`"a token"`, `[1]`, `{}`} {
		if _, err := credentialsOf("", proofs); kindOf(err) != kindInvalidArgument {
			t.Errorf("proofs %s: %v, want invalid_argument", proofs, err)
		}
	}
	if c, err := credentialsOf("", ""); err != nil || c.token != nil || c.proofs != nil {
		t.Errorf("no credentials: %+v, %v", c, err)
	}
}

func mustHex(t *testing.T, text string) []byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// gatedFleet is a fleet whose org procedure, served by provider on the first
// station, is gated on root.
type gatedFleet struct {
	fleet
	realmName        string
	provider, caller *livePool
	root, alice      *identity.NodeKey
	policy           string
}

func newGatedFleet(t *testing.T, name string) gatedFleet {
	t.Helper()
	f := newFleet(t, name)
	g := gatedFleet{fleet: f, realmName: name, provider: f.join(t, name+" provider", f.stations[0]),
		caller: f.join(t, name+" caller", f.stations[1]),
		root:   teststation.Key(t, profile.PQPure, name+" root"), alice: teststation.Key(t, profile.PQPure, name+" alice")}
	f.realm.Admit(t, f.stations[0], g.provider.pool.NodeID())
	g.policy = `{"kind":"ucan_required","issuer":"` + hexNode(t, g.root) + `"}`
	return g
}

// mint is issuer's token to audience granting invoke on with, naming prf.
func (g gatedFleet) mint(t *testing.T, issuer *identity.NodeKey, audience [32]byte, with string, prf ...string) string {
	t.Helper()
	options := ""
	if len(prf) > 0 {
		options = `{"prf":["` + strings.Join(prf, `","`) + `"]}`
	}
	token, err := ucanCreate(issuer, audience, fmt.Sprintf(`[{"with":%q,"can":"invoke"}]`, with),
		time.Now().Unix()+60, options)
	if err != nil {
		t.Fatalf("ucanCreate: %v", err)
	}
	return token
}

// presentations are what a caller presents to the gated procedure, each with
// the provider's answer: "" to serve it, else the code it refuses with.
func (g gatedFleet) presentations(t *testing.T, procedure string) map[string]struct{ token, proofs, want string } {
	t.Helper()
	org := "mri:org:" + g.realmName + "/" + g.realm.Org
	caller := g.caller.pool.NodeID()
	aliceID, _ := g.alice.NodeID()
	direct := g.mint(t, g.root, caller, org)
	toAlice := g.mint(t, g.root, aliceID, org)
	chained := g.mint(t, g.alice, caller, "mri:proc:"+g.realmName+"/"+procedure, ucan.ProofID([]byte(toAlice)))
	return map[string]struct{ token, proofs, want string }{
		"a root token":          {direct, "", ""},
		"a delegated chain":     {chained, `["` + toAlice + `"]`, ""},
		"no token":              {"", "", "unauthorized"},
		"a chain without proof": {chained, "", "unauthorized"},
		"an unreferenced proof": {direct, `["` + toAlice + `"]`, "malformed_frame"},
	}
}

// A procedure served gated through the ABI serves a caller presenting its
// issuer's grant with macula_pool_call_with, and answers the rest with a
// provider error of macula's code.
func TestAGatedProcedureThroughTheABI(t *testing.T) {
	g := newGatedFleet(t, "gated")
	procedure := g.realm.Org + "/count"
	policy, err := gatedPolicy(g.policy)
	if err != nil {
		t.Fatal(err)
	}
	s, err := serve(g.provider, g.realm.ID, procedure, serveOptions{policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			item, state := s.box.next(ctx)
			cancel()
			if state != inboxItemReady {
				return
			}
			if pc, ok := valueOf[*pendingCall](item.handle); ok {
				v, _ := payloadFromJSON(`"served"`)
				_ = pc.answer(pendingAnswer{payload: v})
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for name, c := range g.presentations(t, procedure) {
		creds, err := credentialsOf(c.token, c.proofs)
		if err != nil {
			t.Fatal(err)
		}
		result, err := callUntilProvided(ctx, g.caller, g.realm.ID, procedure, callOptions{creds: creds})
		switch e := classify(ctx, err); {
		case c.want == "" && (err != nil || result != `"served"`):
			t.Errorf("%s: %q, %v", name, result, err)
		case c.want != "" && (e == nil || e.kind != kindProviderError || e.fields["code"] != c.want):
			t.Errorf("%s: %v, want provider_error %s", name, err, c.want)
		}
	}
}

// callUntilProvided calls until a provider answers, with a result or an
// error, or the pool decides the call cannot be kept confidential: the
// advertisement reaches the other station's DHT in its own time.
func callUntilProvided(ctx context.Context, lp *livePool, realm [32]byte, procedure string, opts callOptions) (string, error) {
	for {
		result, err := call(ctx, lp.pool, realm, procedure, `null`, 5*time.Second, opts)
		if kind := classify(ctx, err).kind; err == nil || kind == kindProviderError || kind == kindConfidentiality || ctx.Err() != nil {
			return result, err
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// A stream served gated through the ABI opens for a caller presenting its
// issuer's grant with macula_pool_open_stream_with, and is refused with a
// stream error of macula's code otherwise.
func TestAGatedStreamThroughTheABI(t *testing.T) {
	g := newGatedFleet(t, "gatedstream")
	procedure := g.realm.Org + "/watch"
	policy, err := gatedPolicy(g.policy)
	if err != nil {
		t.Fatal(err)
	}
	s, err := serveStream(g.provider, g.realm.ID, procedure, frame.ServerStream, serveOptions{policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			item, state := s.box.next(ctx)
			cancel()
			if state != inboxItemReady {
				return
			}
			if session, ok := valueOf[*stationlink.Stream](item.handle); ok {
				v, _ := payloadFromJSON(`"served"`)
				_ = session.Reply(v)
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for name, c := range g.presentations(t, procedure) {
		creds, err := credentialsOf(c.token, c.proofs)
		if err != nil {
			t.Fatal(err)
		}
		first := openUntilProvided(ctx, t, g.caller, g.realm.ID, procedure, callOptions{creds: creds})
		switch {
		case c.want == "" && !strings.Contains(first, `"payload":"served"`):
			t.Errorf("%s: %s", name, first)
		case c.want != "" && !strings.Contains(first, `"code":"`+c.want+`"`):
			t.Errorf("%s: %s, want a stream error %s", name, first, c.want)
		}
	}
}

// openUntilProvided opens the stream until its provider, not a relay, answers,
// and returns the first frame it sends.
func openUntilProvided(ctx context.Context, t *testing.T, lp *livePool, realm [32]byte, procedure string, opts callOptions) string {
	t.Helper()
	for {
		stream, err := openStream(ctx, lp.pool, realm, procedure, frame.ServerStream, `null`, 10*time.Second, opts)
		if err == nil {
			out, err := recvJSON(ctx, stream)
			_ = stream.Close()
			if err == nil && !strings.Contains(out, `"relay":1`) {
				return out
			}
		}
		if ctx.Err() != nil {
			t.Fatalf("no provider answered: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
