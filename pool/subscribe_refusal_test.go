package pool

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// subscribed subscribes through the pool and reports a refusal, which a valid
// realm and topic never meet. It reports with t.Errorf, so a goroutine may call
// it.
func subscribed(t *testing.T, p *Pool, realm []byte, topic string, handler EventHandler) SubID {
	t.Helper()
	id, err := p.Subscribe(realm, topic, handler)
	if err != nil {
		t.Errorf("Subscribe(%q): %v", topic, err)
	}
	return id
}

// A subscription a station refuses costs that subscription alone: Subscribe
// returns the refusal before anything is registered, so no link sends a
// SUBSCRIBE for it or fails, and a valid subscription beside it still
// subscribes.
func TestASubscriptionAStationRefusesIsReturnedAndNoLinkSeesIt(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s, newFakeSession())

	var mu sync.Mutex
	var downs int
	opts := testOpts(id, dialer.dial)
	opts.OnLinkEvent = func(_ string, up bool, _ error) {
		mu.Lock()
		defer mu.Unlock()
		if !up {
			downs++
		}
	}
	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0x5A)
	for _, c := range []struct {
		name  string
		realm []byte
		topic string
		want  error
	}{
		{"a 31-byte realm", realm[:31], "sensors/kitchen", frame.ErrOutOfRange},
		{"a 513-byte topic", realm, strings.Repeat("t", 513), frame.ErrTextTooLong},
		{"a topic that is not UTF-8", realm, "\xff", frame.ErrInvalidText},
	} {
		subID, err := p.Subscribe(c.realm, c.topic, func([]byte, string, cbor.Value) {})
		if subID != 0 || !errors.Is(err, c.want) {
			t.Errorf("Subscribe with %s: (%d, %v), want (0, %v)", c.name, subID, err, c.want)
		}
	}
	p.subsMu.Lock()
	registered, topics := len(p.subs), len(p.topicIndex)
	p.subsMu.Unlock()
	if registered != 0 || topics != 0 {
		t.Errorf("after the refused subscriptions the pool holds %d subscriptions and %d topics, want none", registered, topics)
	}

	subscribed(t, p, realm, "sensors/kitchen", func([]byte, string, cbor.Value) {})
	// A link that met a refused subscription would fail at once and redial
	// after RespawnDelay (20ms here): give that time to show before looking.
	time.Sleep(200 * time.Millisecond)
	mu.Lock()
	gotDowns := downs
	mu.Unlock()
	if dials := dialer.dialCount("station.example", 4433); dials != 1 || gotDowns != 0 {
		t.Errorf("after the refused subscriptions the link dialed %d times and went down %d times, want 1 and 0", dials, gotDowns)
	}
	sent := subscribeFrames(s.Sent())
	if len(sent) != 1 {
		t.Fatalf("SUBSCRIBE frames on the first session: %d, want 1, for the valid subscription alone", len(sent))
	}
	if topic, err := parseSubscribeTopic(sent[0]); err != nil || topic != "sensors/kitchen" {
		t.Errorf("the SUBSCRIBE's topic: (%q, %v), want sensors/kitchen", topic, err)
	}
}
