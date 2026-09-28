package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/stationlink"
)

// The seal report through the ABI (macula's DESIGN_E2E_SEAL_REPORT §6):
// "report": 1 in a call's options turns its reply into {"result", "sealed",
// "provider", "seal_key_id"}; macula_stream_report gives a stream's once it
// has settled, else the kind not_settled, and not_a_caller on a served one.

func TestReportOptionsAreChecked(t *testing.T) {
	for _, text := range []string{`{"report":2}`, `{"report":true}`, `{"report":"1"}`} {
		if _, err := callOptionsOf(text); kindOf(err) != kindInvalidArgument {
			t.Errorf("call options %s: %v, want invalid_argument", text, err)
		}
	}
	if opts, err := callOptionsOf(`{"report":1}`); err != nil || !opts.report {
		t.Errorf(`{"report":1}: %+v, %v`, opts, err)
	}
	if opts, err := callOptionsOf(`{"report":0}`); err != nil || opts.report {
		t.Errorf(`{"report":0}: %+v, %v`, opts, err)
	}
	// A stream reports through macula_stream_report, never through its open.
	if _, err := openOptionsOf(`{"report":1}`); kindOf(err) != kindInvalidArgument {
		t.Errorf("an open's report: %v, want invalid_argument", err)
	}
	if _, err := openOptionsOf(`{"confidential":"required"}`); err != nil {
		t.Errorf("an open's options: %v", err)
	}
}

func TestTheReportsErrorKinds(t *testing.T) {
	if k := classify(nil, stationlink.ErrNotSettled).kind; k != kindNotSettled {
		t.Errorf("ErrNotSettled: %s", k)
	}
	if k := classify(nil, stationlink.ErrNotACaller).kind; k != kindNotACaller {
		t.Errorf("ErrNotACaller: %s", k)
	}
}

type reportEnvelope struct {
	Result    json.RawMessage `json:"result"`
	Sealed    *int            `json:"sealed"`
	Provider  string          `json:"provider"`
	SealKeyID *string         `json:"seal_key_id"`
}

func TestACallReportThroughTheABI(t *testing.T) {
	f := newFleet(t, "reportabi")
	provider := f.joinKeyed(t, "report abi provider")
	keyless := f.join(t, "report abi keyless", f.stations[0])
	caller := f.join(t, "report abi caller", f.stations[1])
	f.realm.Admit(t, f.stations[0], provider.pool.NodeID(), keyless.pool.NodeID())
	for _, c := range []struct {
		lp        *livePool
		procedure string
		sealed    int
	}{{provider, f.realm.Org + "/vault", 1}, {keyless, f.realm.Org + "/open", 0}} {
		s, err := serve(c.lp, f.realm.ID, c.procedure, serveOptions{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.stop() })
		go answerAll(s, `"kept"`)
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		out, err := callUntilProvided(ctx, caller, f.realm.ID, c.procedure, callOptions{report: true})
		cancel()
		var got reportEnvelope
		if err != nil || json.Unmarshal([]byte(out), &got) != nil {
			t.Fatalf("%s: %q, %v", c.procedure, out, err)
		}
		node := c.lp.pool.NodeID()
		switch {
		case string(got.Result) != `"kept"`, got.Sealed == nil, *got.Sealed != c.sealed,
			got.Provider != hex.EncodeToString(node[:]):
			t.Errorf("%s: %s", c.procedure, out)
		case c.sealed == 1 && (got.SealKeyID == nil || len(*got.SealKeyID) != 16):
			t.Errorf("%s: a sealed call names no key: %s", c.procedure, out)
		case c.sealed == 0 && got.SealKeyID != nil:
			t.Errorf("%s: a clear call names a key: %s", c.procedure, out)
		}
	}
	// Without "report" the reply is the result, as before.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if out, err := callUntilProvided(ctx, caller, f.realm.ID, f.realm.Org+"/vault", callOptions{}); err != nil || out != `"kept"` {
		t.Errorf("an unreported call: %q, %v", out, err)
	}
}

func TestAStreamReportThroughTheABI(t *testing.T) {
	f := newFleet(t, "streamreportabi")
	provider := f.joinKeyed(t, "stream report provider")
	caller := f.join(t, "stream report caller", f.stations[1])
	f.realm.Admit(t, f.stations[0], provider.pool.NodeID())
	procedure := f.realm.Org + "/watch"
	s, err := serveStream(provider, f.realm.ID, procedure, frame.ServerStream, serveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })
	served := make(chan string, 1)
	release := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		item, state := s.box.next(ctx)
		if state != inboxItemReady {
			return
		}
		if session, ok := valueOf[*stationlink.Stream](item.handle); ok {
			_, err := streamReportJSON(session)
			served <- string(classify(nil, err).kind)
			<-release
			_ = session.Reply(must(payloadFromJSON(`"watched"`)))
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var stream *stationlink.Stream
	for stream == nil {
		stream, err = openStream(ctx, caller.pool, f.realm.ID, procedure, frame.ServerStream, `null`, 10*time.Second, callOptions{})
		if err != nil {
			if ctx.Err() != nil {
				t.Fatalf("no provider answered: %v", err)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	defer stream.Close()
	if kind := <-served; kind != string(kindNotACaller) {
		t.Errorf("a served stream's report: %s, want not_a_caller", kind)
	}
	if _, err := streamReportJSON(stream); classify(nil, err).kind != kindNotSettled {
		t.Errorf("before the first frame: %v, want not_settled", err)
	}
	close(release)
	if _, err := recvJSON(ctx, stream); err != nil {
		t.Fatal(err)
	}
	out, err := streamReportJSON(stream)
	var got reportEnvelope
	node := provider.pool.NodeID()
	if err != nil || json.Unmarshal([]byte(out), &got) != nil || got.Sealed == nil || *got.Sealed != 1 ||
		got.Provider != hex.EncodeToString(node[:]) || got.SealKeyID == nil || len(*got.SealKeyID) != 16 {
		t.Errorf("a settled stream's report: %q, %v", out, err)
	}
}

// answerAll answers every call served on s with result.
func answerAll(s *served, result string) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		item, state := s.box.next(ctx)
		cancel()
		if state != inboxItemReady {
			return
		}
		if pc, ok := valueOf[*pendingCall](item.handle); ok {
			_ = pc.answer(pendingAnswer{payload: must(payloadFromJSON(result))})
		}
	}
}
