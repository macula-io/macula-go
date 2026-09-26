package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// The ABI's Go side against in-process macula 12 stations: each test drives
// the functions the exports call, with the JSON a binding sends.

type fleet struct {
	stations []*teststation.Station
	realm    teststation.Realm
}

func newFleet(t *testing.T, name string) fleet {
	t.Helper()
	a := teststation.Start(t, profile.PQPure, name+" a")
	b := teststation.Start(t, profile.PQPure, name+" b")
	teststation.ShareDHT(a, b)
	return fleet{stations: []*teststation.Station{a, b}, realm: teststation.NewRealm(t, profile.PQPure, name, "mcl-"+name)}
}

func (f fleet) seedsJSON(stations ...*teststation.Station) string {
	type seed struct {
		Host   string `json:"host"`
		Port   uint16 `json:"port"`
		NodeID string `json:"node_id"`
	}
	var seeds []seed
	for _, s := range stations {
		seeds = append(seeds, seed{Host: s.Host, Port: s.Port, NodeID: hex.EncodeToString(s.NodeID[:])})
	}
	text, _ := json.Marshal(seeds)
	return string(text)
}

func (f fleet) optionsJSON() string {
	return fmt.Sprintf(`{"realm_trust": {%q: %q}, "respawn_delay_ms": 100, "timeout_ms": 20000}`,
		hex.EncodeToString(f.realm.ID[:]), hex.EncodeToString(f.realm.RealmKey()))
}

// join connects a node named name to one station of the fleet.
func (f fleet) join(t *testing.T, name string, station *teststation.Station) *livePool {
	t.Helper()
	lp, err := connect(context.Background(), teststation.Key(t, profile.PQPure, name), f.seedsJSON(station), f.optionsJSON())
	if err != nil {
		t.Fatalf("%s: connect: %v", name, err)
	}
	t.Cleanup(lp.close)
	return lp
}

func ownProcedure(lp *livePool, name string) string {
	id := lp.pool.NodeID()
	return "~" + hex.EncodeToString(id[:]) + "/" + name
}

func kindOf(err error) errorKind { return classify(nil, err).kind }

// sameValue checks two JSON payloads carry the same value: map keys come out
// in the wire's deterministic order, not the order they went in.
func sameValue(t *testing.T, what, got, want string) {
	t.Helper()
	g, err := payloadFromJSON(got)
	if err != nil {
		t.Fatalf("%s: %s: %v", what, got, err)
	}
	w, err := payloadFromJSON(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(cbor.Encode(g)) != string(cbor.Encode(w)) {
		t.Fatalf("%s: %s, want %s", what, got, want)
	}
}

// answerNext takes the next call off a served procedure's inbox and answers
// it with answer, returning its request.
func answerNext(t *testing.T, s *served, answer func(*pendingCall, map[string]any)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	item, state := s.box.next(ctx)
	if state != inboxItemReady {
		t.Errorf("no call arrived: %v", state)
		return
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(item.json), &request); err != nil {
		t.Error(err)
		return
	}
	pending, ok := valueOf[*pendingCall](item.handle)
	if !ok {
		t.Error("the call's handle is not a pending call")
		return
	}
	answer(pending, request)
}

func TestConnectReportsItsLinks(t *testing.T) {
	f := newFleet(t, "links")
	lp := f.join(t, "linker", f.stations[0])
	var links []map[string]any
	if err := json.Unmarshal([]byte(statusJSON(lp.pool)), &links); err != nil {
		t.Fatal(err)
	}
	if len(links) != 1 || links[0]["up"] != float64(1) {
		t.Fatalf("status: %v", links)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	item, state := lp.events.next(ctx)
	if state != inboxItemReady || !strings.Contains(item.json, `"kind":"link"`) || !strings.Contains(item.json, `"up":1`) {
		t.Fatalf("the first pool event: %q, %v", item.json, state)
	}
}

func TestConnectRefusesBadArguments(t *testing.T) {
	f := newFleet(t, "refusals")
	key := teststation.Key(t, profile.PQPure, "refused")
	for name, c := range map[string][2]string{
		"seeds that are not JSON":     {`[`, ""},
		"a misspelt option":           {f.seedsJSON(f.stations[0]), `{"realm_trusts": {}}`},
		"a short seed node_id":        {`[{"host":"127.0.0.1","port":1,"node_id":"00"}]`, ""},
		"a realm key that is not hex": {f.seedsJSON(f.stations[0]), fmt.Sprintf(`{"realm_trust": {%q: "zz"}}`, strings.Repeat("00", 32))},
	} {
		if _, err := connect(context.Background(), key, c[0], c[1]); kindOf(err) != kindInvalidArgument {
			t.Errorf("%s: %v, want invalid_argument", name, err)
		}
	}
}

func TestCallsReachAServedProcedure(t *testing.T) {
	f := newFleet(t, "calls")
	provider := f.join(t, "provider", f.stations[0])
	caller := f.join(t, "caller", f.stations[1])
	procedure := ownProcedure(provider, "echo")
	s, err := serve(provider, f.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })

	go answerNext(t, s, func(pc *pendingCall, request map[string]any) {
		result, _ := payloadFromJSON(`{"echo": 9223372036854775807, "raw": {"$bytes": "AQI="}}`)
		if request["procedure"] != procedure {
			t.Errorf("request: %v", request)
		}
		if err := pc.answer(pendingAnswer{payload: result}); err != nil {
			t.Error(err)
		}
		if err := pc.answer(pendingAnswer{payload: result}); kindOf(err) != kindAnswered {
			t.Errorf("a second answer: %v, want answered", err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := call(ctx, caller.pool, f.realm.ID, procedure, `{"n": 1}`, nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	sameValue(t, "result", result, `{"echo": 9223372036854775807, "raw": {"$bytes": "AQI="}}`)

	go answerNext(t, s, func(pc *pendingCall, _ map[string]any) {
		_ = pc.answer(pendingAnswer{err: errors.New("no such thing")})
	})
	_, err = call(ctx, caller.pool, f.realm.ID, procedure, `null`, nil, 10*time.Second)
	e := classify(ctx, err)
	if e.kind != kindProviderError || e.fields["code"] != "handler_error" || e.fields["detail"] != "no such thing" {
		t.Fatalf("an error answer: %v", e.JSON())
	}
}

func TestACancelledCallSaysSo(t *testing.T) {
	f := newFleet(t, "cancel")
	provider := f.join(t, "slow provider", f.stations[0])
	caller := f.join(t, "impatient caller", f.stations[1])
	procedure := ownProcedure(provider, "never")
	s, err := serve(provider, f.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })

	token := newCancelToken()
	ctx, cancel, _ := withTimeout(token.ctx, 0)
	defer cancel()
	go func() {
		time.Sleep(500 * time.Millisecond)
		token.cancel(errTokenCancelled)
	}()
	started := time.Now()
	_, err = call(ctx, caller.pool, f.realm.ID, procedure, `null`, nil, 30*time.Second)
	if got := classify(ctx, err).kind; got != kindCancelled {
		t.Fatalf("a cancelled call: %v (%s), want cancelled", err, got)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the cancelled call took %v", elapsed)
	}
}

func TestOrgProceduresNeedTheirDelegation(t *testing.T) {
	f := newFleet(t, "org")
	provider := f.join(t, "org provider", f.stations[0])
	caller := f.join(t, "org caller", f.stations[1])
	f.realm.Admit(t, f.stations[0], provider.pool.NodeID())
	procedure := f.realm.Org + "/greet"
	s, err := serve(provider, f.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	go answerNext(t, s, func(pc *pendingCall, _ map[string]any) {
		v, _ := payloadFromJSON(`"hello"`)
		_ = pc.answer(pendingAnswer{payload: v})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var result string
	for {
		result, err = call(ctx, caller.pool, f.realm.ID, procedure, `null`, nil, 5*time.Second)
		if err == nil || ctx.Err() != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || result != `"hello"` {
		t.Fatalf("an org call: %q, %v", result, err)
	}
}

func TestSubscriptionsHearPublications(t *testing.T) {
	f := newFleet(t, "pubsub")
	publisher := f.join(t, "publisher", f.stations[0])
	listener := f.join(t, "listener", f.stations[0])
	sub, err := subscribe(listener, f.realm.ID, "news")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for !f.stations[0].Subscribed(listener.pool.NodeID(), f.realm.ID, "news") && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if err := publish(publisher.pool, f.realm.ID, "news", `{"headline": "cabi", "seq": 9007199254740993}`, 0); err != nil {
		t.Fatal(err)
	}
	item, state := sub.box.next(ctx)
	if state != inboxItemReady {
		t.Fatalf("no event: %v", state)
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal([]byte(item.json), &event); err != nil {
		t.Fatal(err)
	}
	sameValue(t, "event payload", string(event["payload"]), `{"headline": "cabi", "seq": 9007199254740993}`)
	if err := publish(publisher.pool, f.realm.ID, "news", `true`, 0); kindOf(err) != kindInvalidArgument {
		t.Fatalf("a boolean publication: %v", err)
	}
	sub.stop()
	if _, state := sub.box.next(ctx); state != inboxClosed {
		t.Fatalf("a stopped subscription: %v, want closed", state)
	}
}

func TestServedStreamsRunBothWays(t *testing.T) {
	f := newFleet(t, "streams")
	provider := f.join(t, "stream provider", f.stations[0])
	caller := f.join(t, "stream caller", f.stations[1])
	procedure := ownProcedure(provider, "count")
	s, err := serveStream(provider, f.realm.ID, procedure, frame.ServerStream)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		item, state := s.box.next(ctx)
		if state != inboxItemReady {
			t.Errorf("no session: %v", state)
			return
		}
		session, ok := valueOf[*stationlink.Stream](item.handle)
		if !ok {
			t.Error("the session's handle is not a stream")
			return
		}
		one, _ := payloadFromJSON(`{"n": 1}`)
		_ = session.SendValue(one)
		_ = session.Send([]byte{7, 8})
		done, _ := payloadFromJSON(`"done"`)
		_ = session.Reply(done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stream, err := openStream(ctx, caller.pool, f.realm.ID, procedure, frame.ServerStream, `{"to": 1}`, nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	var frames []string
	for {
		out, err := recvJSON(ctx, stream)
		if err != nil {
			t.Fatalf("recv: %v", err)
		}
		frames = append(frames, out)
		if strings.Contains(out, `"kind":"eof"`) || strings.Contains(out, `"kind":"error"`) {
			break
		}
	}
	joined := strings.Join(frames, "\n")
	for _, want := range []string{`"body":{"n":1}`, `"body":{"$bytes":"Bwg="}`, `"kind":"reply"`, `"payload":"done"`, `"kind":"eof"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("the frames lack %s:\n%s", want, joined)
		}
	}
}

func TestContentIsSharedAndFetched(t *testing.T) {
	f := newFleet(t, "content")
	sharer := f.join(t, "sharer", f.stations[0])
	fetcher := f.join(t, "fetcher", f.stations[1])
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data := []byte(strings.Repeat("macula ", 50_000))
	mcid, err := sharer.pool.ShareContent(ctx, f.realm.ID, data, "big.txt")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseContentOptions(`{"parallel": 2}`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := fetcher.pool.GetContent(ctx, f.realm.ID, mcid, opts)
	if err != nil || string(got) != string(data) {
		t.Fatalf("fetch: %d bytes, %v", len(got), err)
	}
	if err := sharer.pool.UnshareContent(ctx, f.realm.ID, mcid); err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.pool.GetContent(ctx, f.realm.ID, mcid, opts); kindOf(err) != kindNotShared {
		t.Fatalf("after unsharing: %v, want not_shared", err)
	}
	if _, err := parseContentOptions(`{"paralel": 2}`); kindOf(err) != kindInvalidArgument {
		t.Fatalf("a misspelt content option: %v", err)
	}
}

func TestRecordsAreFoundOrNotFound(t *testing.T) {
	f := newFleet(t, "records")
	lp := f.join(t, "reader", f.stations[0])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	var missing [32]byte
	missing[0] = 0xee
	if _, err := findRecord(ctx, lp.pool, missing); kindOf(err) != kindNotFound {
		t.Fatalf("a missing record: %v, want not_found", err)
	}
	if _, err := findRecordsByType(ctx, lp.pool, 0); kindOf(err) != kindInvalidArgument {
		t.Fatalf("record type 0: %v", err)
	}
	// Every teststation puts its own station endpoint record.
	out, err := findRecordsByType(ctx, lp.pool, int32(record.TypeStationEndpoint))
	if err != nil {
		t.Fatal(err)
	}
	var found struct {
		Records []map[string]any `json:"records"`
	}
	if err := json.Unmarshal([]byte(out), &found); err != nil || len(found.Records) == 0 {
		t.Fatalf("station endpoint records: %s, %v", out, err)
	}
}

func TestClosingAPoolEndsWhatItOwns(t *testing.T) {
	f := newFleet(t, "closing")
	lp := f.join(t, "closer", f.stations[0])
	sub, err := subscribe(lp, f.realm.ID, "t")
	if err != nil {
		t.Fatal(err)
	}
	s, err := serve(lp, f.realm.ID, ownProcedure(lp, "x"))
	if err != nil {
		t.Fatal(err)
	}
	lp.close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for name, box := range map[string]*inbox{"subscription": sub.box, "served": s.box, "events": lp.events} {
		for {
			_, state := box.next(ctx)
			if state == inboxItemReady {
				continue
			}
			if state != inboxClosed {
				t.Errorf("%s after the pool closed: %v, want closed", name, state)
			}
			break
		}
	}
}

// A call in flight when its own pool closes ends as closed.
func TestACallInFlightWhenItsPoolClosesIsClosed(t *testing.T) {
	f := newFleet(t, "close in flight")
	provider := f.join(t, "silent", f.stations[0])
	lp, err := connect(context.Background(), teststation.Key(t, profile.PQPure, "closing caller"), f.seedsJSON(f.stations[1]), f.optionsJSON())
	if err != nil {
		t.Fatal(err)
	}
	procedure := ownProcedure(provider, "never")
	s, err := serve(provider, f.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() {
		_, err := call(ctx, lp.pool, f.realm.ID, procedure, `null`, nil, 20*time.Second)
		done <- err
	}()
	// The call has reached the provider when it waits in its inbox.
	taken, state := s.box.next(ctx)
	if state != inboxItemReady {
		t.Fatalf("the call never arrived: %v", state)
	}
	_ = taken
	lp.close()
	select {
	case err := <-done:
		if got := classify(ctx, err); got.kind != kindClosed {
			t.Fatalf("a call in flight when its pool closed: %s (%v), want closed", got.kind, err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not end when its pool closed")
	}
}

// A pending call answered after its deadline is "answered": the call was
// answered for it. Its handle then ends, like any answered call's.
func TestALateAnswerIsAnswered(t *testing.T) {
	f := newFleet(t, "late")
	provider := f.join(t, "late provider", f.stations[0])
	caller := f.join(t, "late caller", f.stations[1])
	procedure := ownProcedure(provider, "slow")
	s, err := serve(provider, f.realm.ID, procedure)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go func() { _, _ = call(ctx, caller.pool, f.realm.ID, procedure, `null`, nil, time.Second) }()
	item, state := s.box.next(ctx)
	if state != inboxItemReady {
		t.Fatalf("no call: %v", state)
	}
	time.Sleep(2 * time.Second)
	result, _ := payloadFromJSON(`"too late"`)
	if err := answerPendingHandle(item.handle, pendingAnswer{payload: result}); kindOf(err) != kindAnswered {
		t.Fatalf("a late answer: %v, want answered", err)
	}
	if err := answerPendingHandle(item.handle, pendingAnswer{payload: result}); kindOf(err) != kindInvalidHandle {
		t.Fatalf("an answer after the handle ended: %v, want invalid_handle", err)
	}
}
