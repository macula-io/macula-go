package stationlink

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// Every way a link ends has the name every macula SDK gives it.
func TestEndReasonNamesHowALinkEnded(t *testing.T) {
	cases := map[string]error{
		"liveness_lost":     ErrLivenessLost,
		"closed":            ErrClosed,
		"goodbye":           &GoodbyeError{Reason: "station_draining"},
		"status_expired":    ErrStatusExpired,
		"binding_expired":   ErrBindingExpired,
		"malformed_frame":   fmt.Errorf("%w: event", frame.ErrMalformedFrame),
		"idle_timeout":      &quic.IdleTimeoutError{},
		"closed_by_station": &quic.ApplicationError{Remote: true, ErrorMessage: "dropped"},
		"connection_lost":   errors.New("read: connection reset"),
	}
	for want, err := range cases {
		if got := EndReason(err); got != want {
			t.Errorf("EndReason(%v) = %q, want %q", err, got, want)
		}
	}
	if got := EndReason(&quic.ApplicationError{Remote: false}); got != "connection_lost" {
		t.Errorf("a connection this side closed is %q, want connection_lost", got)
	}
}

// A link's last heard moves with each frame it reads from its station.
func TestLastHeardMovesWithEachFrameRead(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(publish cbor.Value) []cbor.Value { return []cbor.Value{eventOf(publish)} })
	sub, err := link.Subscribe(testRealm, testTopic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	heard := link.LastHeard()
	if now := uint64(time.Now().UnixMilli()); heard == 0 || heard > now {
		t.Fatalf("last heard %d after the ack, want a time up to now %d", heard, now)
	}
	time.Sleep(20 * time.Millisecond)
	if err := link.Publish(Publication{Realm: testRealm, Topic: testTopic, Payload: cbor.Text("headline")}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case <-sub.Events():
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
	}
	// The link records the frame once it handled it, after the event left.
	deadline := time.Now().Add(time.Second)
	for link.LastHeard() <= heard {
		if time.Now().After(deadline) {
			t.Fatalf("last heard %d after an EVENT, want later than %d", link.LastHeard(), heard)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
