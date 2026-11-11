package main

import (
	"context"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/ucan"
	"strings"
	"testing"
	"time"
)

// A call whose station link ends reports the kind a binding already knows,
// failed, and its message names the ending: the macOS/ts caller that read the
// transport's own close has SDK words to read instead (macula-go#75,
// macula-sponsors#484).
func TestADroppedCallReportsFailedAndNamesTheEnding(t *testing.T) {
	f := newFleet(t, "link ended")
	provider := f.join(t, "ended provider", f.stations[0])
	caller := f.join(t, "ended caller", f.stations[1])
	procedure := ownProcedure(provider, "held")
	s, err := serve(provider, f.realm.ID, procedure, serveOptions{policy: ucan.Open{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.stop() })

	inFlight := make(chan struct{}, 1)
	release := make(chan struct{})
	go answerNext(t, s, func(pc *pendingCall, _ map[string]any) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-release
		_ = pc.answer(pendingAnswer{payload: cbor.Map(nil)})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out := make(chan error, 1)
	go func() {
		_, err := call(ctx, caller.pool, f.realm.ID, procedure, `null`, 20*time.Second, callOptions{})
		out <- err
	}()
	select {
	case <-inFlight:
	case <-time.After(20 * time.Second):
		t.Fatal("the call never reached the provider")
	}
	// The caller's own link to the serving station ends under the call.
	f.stations[0].Drop(caller.pool.NodeID())
	var callErr error
	select {
	case callErr = <-out:
	case <-time.After(30 * time.Second):
		t.Fatal("the call never returned after its link ended")
	}
	close(release)

	e := classify(ctx, callErr)
	if e.kind != kindFailed {
		t.Fatalf("a dropped call: %s, want failed: %v", e.kind, callErr)
	}
	message, _ := errorJSON(t, e)["message"].(string)
	if !strings.Contains(message, "(closed_by_station)") {
		t.Errorf("the message does not name the ending: %q", message)
	}
}
