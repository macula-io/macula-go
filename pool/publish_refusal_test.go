package pool

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// A publication a station refuses, and drops without a reply, is returned to
// its caller before any link is touched, as a payload the wire cannot carry is:
// a realm that is not 32 bytes, checked before the topic and the payload, and a
// topic over 512 bytes or not UTF-8. A valid publish beside them is written.
func TestAPublicationAStationRefusesIsReturnedWithoutTouchingAnyLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0x01)
	dup := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("dup"), Val: cbor.Uint64(1)},
		{Key: cbor.Text("dup"), Val: cbor.Uint64(2)},
	})
	for _, c := range []struct {
		name    string
		realm   []byte
		topic   string
		payload cbor.Value
		want    error
	}{
		{"a 31-byte realm", realm[:31], "some.topic", cbor.Uint64(1), frame.ErrOutOfRange},
		{"a 31-byte realm and a duplicate-key payload", realm[:31], "some.topic", dup, frame.ErrOutOfRange},
		{"a 513-byte topic", realm, strings.Repeat("t", 513), cbor.Uint64(1), frame.ErrTextTooLong},
		{"a topic that is not UTF-8", realm, "\xff", cbor.Uint64(1), frame.ErrInvalidText},
	} {
		if err := p.Publish(c.realm, c.topic, c.payload); !errors.Is(err, c.want) {
			t.Errorf("Publish with %s: %v, want %v", c.name, err, c.want)
		}
	}
	if attempts, sent := s.publishAttempts(), len(s.Sent()); attempts != 0 || sent != 0 {
		t.Fatalf("after the refused publications the link was asked to publish %d times and sent %d frames, want none", attempts, sent)
	}
	if err := p.Publish(realm, "some.topic", cbor.Uint64(1)); err != nil {
		t.Fatalf("a valid publish after the refusals: %v", err)
	}
	if attempts, sent := s.publishAttempts(), len(s.Sent()); attempts != 1 || sent != 1 {
		t.Errorf("after the valid publish the link was asked to publish %d times and sent %d frames, want 1 and 1", attempts, sent)
	}
}
