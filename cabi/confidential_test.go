package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// Sealed calls and streams through the ABI (macula 13, E2E design): a pool
// connected with kem_advertise names its key, the *_opts functions take
// confidential, and a call that cannot be kept confidential fails with the
// kind confidentiality and its reason.

func TestConfidentialOptionsAreChecked(t *testing.T) {
	for _, text := range []string{`{"confidential":"maybe"}`, `{"confidential":1}`, `{"sealed":1}`, `{"provider":"00"}`,
		`{"proofs":"one"}`} {
		if _, err := callOptionsOf(text); kindOf(err) != kindInvalidArgument {
			t.Errorf("call options %s: %v, want invalid_argument", text, err)
		}
	}
	for _, text := range []string{`{"confidential":"maybe"}`, `{"policy":{"kind":"open"}}`, `{"hint":1}`} {
		if _, err := serveOptionsOf(text); kindOf(err) != kindInvalidArgument {
			t.Errorf("serve options %s: %v, want invalid_argument", text, err)
		}
	}
	opts, err := callOptionsOf(`{"confidential":"required","ucan":"t","proofs":["p"]}`)
	if err != nil || opts.confidential != stationlink.ConfidentialRequired || string(opts.creds.token) != "t" || len(opts.creds.proofs) != 1 {
		t.Errorf("call options: %+v, %v", opts, err)
	}
	if opts, err := callOptionsOf(""); err != nil || opts.confidential != stationlink.ConfidentialPreferred {
		t.Errorf("no call options: %+v, %v", opts, err)
	}
	f := newFleet(t, "kemopts")
	seeds := f.seedsJSON(f.stations[0])
	for _, options := range []string{`{"kem_advertise": 2}`, `{"kem_advertise": "yes"}`} {
		if _, err := connect(context.Background(), nil, seeds, options); kindOf(err) != kindInvalidArgument {
			t.Errorf("pool options %s: %v, want invalid_argument", options, err)
		}
	}
}

// joinKeyed is a node that names its KEM key, on one station of the fleet.
func (f fleet) joinKeyed(t *testing.T, name string) *livePool {
	t.Helper()
	options := strings.TrimSuffix(f.optionsJSON(), "}") + `, "kem_advertise": 1}`
	lp, err := connect(context.Background(), teststation.Key(t, profile.PQPure, name), f.seedsJSON(f.stations[0]), options)
	if err != nil {
		t.Fatalf("%s: connect: %v", name, err)
	}
	t.Cleanup(lp.close)
	return lp
}

func TestASealedCallThroughTheABI(t *testing.T) {
	f := newFleet(t, "sealedabi")
	provider := f.joinKeyed(t, "sealed abi provider")
	caller := f.join(t, "sealed abi caller", f.stations[1])
	f.realm.Admit(t, f.stations[0], provider.pool.NodeID())
	procedure := f.realm.Org + "/vault"
	s, err := serve(provider, f.realm.ID, procedure, serveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	requests := make(chan map[string]any, 4)
	go func() {
		for {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			item, state := s.box.next(ctx)
			cancel()
			if state != inboxItemReady {
				return
			}
			var request map[string]any
			_ = json.Unmarshal([]byte(item.json), &request)
			requests <- request
			if pc, ok := valueOf[*pendingCall](item.handle); ok {
				_ = pc.answer(pendingAnswer{payload: must(payloadFromJSON(`"kept"`))})
			}
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	result, err := callUntilProvided(ctx, caller, f.realm.ID, procedure, callOptions{})
	if err != nil || result != `"kept"` {
		t.Fatalf("a preferred call to a keyed provider: %q, %v", result, err)
	}
	if request := <-requests; request["sealed"] != float64(1) {
		t.Errorf("the served request says sealed %v", request["sealed"])
	}
	if _, err := callUntilProvided(ctx, caller, f.realm.ID, procedure, callOptions{confidential: stationlink.ConfidentialOff}); err != nil {
		t.Fatalf("an off call inside the keyless window: %v", err)
	}
	if request := <-requests; request["sealed"] != float64(0) {
		t.Errorf("a clear request says sealed %v", request["sealed"])
	}

	keyless := f.join(t, "keyless abi provider", f.stations[0])
	f.realm.Admit(t, f.stations[0], keyless.pool.NodeID())
	open := f.realm.Org + "/open"
	ks, err := serve(keyless, f.realm.ID, open, serveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ks.stop() })
	_, err = callUntilProvided(ctx, caller, f.realm.ID, open, callOptions{confidential: stationlink.ConfidentialRequired})
	e := classify(ctx, err)
	if e.kind != kindConfidentiality || e.fields["reason"] != "no_kem_key" {
		t.Errorf("a required call to a keyless provider: %s", e.JSON())
	}
	if _, err := serve(keyless, f.realm.ID, f.realm.Org+"/strict", serveOptions{confidential: stationlink.ConfidentialRequired}); classify(nil, err).kind != kindConfidentiality {
		t.Errorf("a required serve without kem_advertise: %v", err)
	}
}

func TestASealedStreamThroughTheABI(t *testing.T) {
	f := newFleet(t, "sealedstreamabi")
	provider := f.joinKeyed(t, "sealed stream provider")
	caller := f.join(t, "sealed stream caller", f.stations[1])
	f.realm.Admit(t, f.stations[0], provider.pool.NodeID())
	procedure := f.realm.Org + "/watch"
	s, err := serveStream(provider, f.realm.ID, procedure, frame.ServerStream, serveOptions{confidential: stationlink.ConfidentialRequired})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		item, state := s.box.next(ctx)
		if state != inboxItemReady {
			return
		}
		if !strings.Contains(item.json, `"sealed":1`) {
			t.Errorf("the session's request: %s", item.json)
		}
		if session, ok := valueOf[*stationlink.Stream](item.handle); ok {
			_ = session.Reply(must(payloadFromJSON(`"sealed reply"`)))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	first := openUntilProvided(ctx, t, caller, f.realm.ID, procedure, callOptions{})
	if !strings.Contains(first, `"payload":"sealed reply"`) {
		t.Errorf("the sealed stream's first frame: %s", first)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
