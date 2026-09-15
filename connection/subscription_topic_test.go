package connection

import (
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/frame"
)

// A subscription a station refuses, to a realm or subscriber that is not 32
// bytes or a topic over 512 bytes or not UTF-8, is refused with frame.Subscribe's
// error before anything is tracked or sent, and the session still subscribes to
// one a station reads.
func TestASubscriptionAStationRefusesSendsNothing(t *testing.T) {
	s, fc, id := readingSession(t)
	cases := []struct {
		name, topic       string
		realm, subscriber []byte
		want              error
	}{
		{"a 31-byte realm", "news/today", testRealm()[:31], id.NodeID(), frame.ErrOutOfRange},
		{"a 31-byte subscriber", "news/today", testRealm(), id.NodeID()[:31], frame.ErrOutOfRange},
		{"a 513-byte topic", strings.Repeat("t", 513), testRealm(), id.NodeID(), frame.ErrTextTooLong},
		{"a topic that is not UTF-8", "\xff", testRealm(), id.NodeID(), frame.ErrInvalidText},
	}
	for _, c := range cases {
		sub, err := s.Subscribe(frame.NewSubscribeSpec(c.topic, c.realm, c.subscriber), id)
		if sub != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: (%v, %v), want it refused with %v", c.name, sub, err, c.want)
		}
	}
	s.rt.mu.Lock()
	tracked, topics := len(s.rt.subs), len(s.rt.topics)
	s.rt.mu.Unlock()
	if tracked != 0 || topics != 0 {
		t.Errorf("after the refused subscriptions the session tracks %d subscriptions and %d topics, want none", tracked, topics)
	}
	mustSubscribe(t, s, id, "news/today")
	fc.awaitSentOfType(t, "subscribe", 1)
	if n := len(fc.sentOfType(t, "subscribe")); n != 1 {
		t.Errorf("SUBSCRIBE frames written: %d, want 1, for the accepted topic alone", n)
	}
}
