//go:build live

// Live-fleet reconnect test — required before this package is
// considered done (per the assignment: "a live-fleet test killing/
// blocking the actual connected station mid-session and confirming
// automatic reconnect"). Run explicitly:
//
//	go test -tags=live ./pool/... -run TestLivePool -v
package pool

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// Same real, live fleet station connection/live_test.go's own live
// tests use.
const (
	liveStationHost = "station-de-frankfurt.macula.io"
	liveStationPort = 4433
)

func TestLivePoolReconnectsAndReplaysSubscriptionAfterLinkDrop(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	p, err := Connect(context.Background(),
		[]Seed{{Host: liveStationHost, Port: liveStationPort}},
		Opts{Identity: id, Trust: transport.WebPKI{}})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, 10*time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	key := linkKey(liveStationHost, liveStationPort)
	p.linksMu.RLock()
	lk := p.links[key]
	p.linksMu.RUnlock()
	originalActor := lk.CurrentActor()
	if originalActor == nil {
		t.Fatalf("no live actor for %s right after Connect reported healthy", key)
	}

	realm := fill32(0x42)
	topic := "pool.live_reconnect_test"

	received := make(chan string, 4)
	p.Subscribe(realm, topic, func(_ []byte, gotTopic string, payload cbor.Value) {
		txt, _ := payload.AsText()
		if gotTopic == topic {
			received <- txt
		}
	})
	time.Sleep(500 * time.Millisecond) // let the wire SUBSCRIBE reach the station before publishing

	// Prove delivery works BEFORE the drop, on the original link.
	if err := p.Publish(realm, topic, cbor.Text("before-drop")); err != nil {
		t.Fatalf("Publish (before drop): %v", err)
	}
	select {
	case got := <-received:
		if got != "before-drop" {
			t.Fatalf("got %q, want %q", got, "before-drop")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("did not receive the pre-drop event within 10s")
	}

	// Simulate the connection dying mid-session: force-close the
	// underlying session out from under the actor. This is the same
	// detection path (Session.Done()'s channel, backed by quic-go's own
	// Conn.Context().Done()) an unexpected network drop would trigger —
	// see connection/live_test.go's TestLiveSessionDoneFiresOnClose,
	// which already proves Close() fires Done().
	_ = originalActor.session.Close("pool_live_test: simulated drop", nil, id)

	// The pool must notice, back off, redial, and come back healthy —
	// with a DIFFERENT actor instance, proving an actual respawn
	// happened rather than the original silently surviving.
	waitFor(t, 15*time.Second, func() bool {
		p.linksMu.RLock()
		lk := p.links[key]
		p.linksMu.RUnlock()
		a := lk.CurrentActor()
		return a != nil && a != originalActor
	})

	// The subscription registered before the drop must have been
	// replayed onto the fresh link, with no action from the caller.
	if err := p.Publish(realm, topic, cbor.Text("after-reconnect")); err != nil {
		t.Fatalf("Publish (after reconnect): %v", err)
	}
	select {
	case got := <-received:
		if got != "after-reconnect" {
			t.Fatalf("got %q, want %q", got, "after-reconnect")
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("subscription was not replayed onto the reconnected link within 10s")
	}
}

// TestLivePoolLivenessProbeDoesNotKillAHealthyLink proves tickLiveness
// (actor.go) doesn't itself destabilize a genuinely healthy connection --
// a short interval so several real _macula.ping round trips happen
// within the test, asserting the link stays up (same actor instance)
// throughout, not just that it eventually reconnects.
func TestLivePoolLivenessProbeDoesNotKillAHealthyLink(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	p, err := Connect(context.Background(),
		[]Seed{{Host: liveStationHost, Port: liveStationPort}},
		Opts{Identity: id, Trust: transport.WebPKI{}, LivenessInterval: 2 * time.Second, LivenessMaxMisses: 2})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, 10*time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	key := linkKey(liveStationHost, liveStationPort)
	p.linksMu.RLock()
	lk := p.links[key]
	p.linksMu.RUnlock()
	original := lk.CurrentActor()

	// Several real liveness ticks (2s interval) against the live
	// station -- if tickLiveness had the miss-counting backwards, or
	// never actually cleared pingCallID on a real reply, this link would
	// die well within this window.
	time.Sleep(9 * time.Second)

	p.linksMu.RLock()
	lk = p.links[key]
	p.linksMu.RUnlock()
	current := lk.CurrentActor()
	if current == nil {
		t.Fatalf("link went down during normal operation with liveness probing active")
	}
	if current != original {
		t.Fatalf("link respawned during normal operation -- the liveness probe itself killed a healthy connection")
	}
}
