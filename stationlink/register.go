package stationlink

import (
	"context"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/frame"
)

// A station answers every ADVERTISE, UNADVERTISE, SUBSCRIBE and UNSUBSCRIBE
// with a REGISTER_ACK (macula docs/design/WIRE_1_0.md section 3.5, macula#12).
// Serve and Subscribe wait for the answer to theirs and return its verdict, as
// macula 15's advertise and subscribe do: an ack answers the registration
// whose kind, realm and name it names, with the record version of an
// advertisement or this node as the subscriber of a subscription.

// registerAckTimeout bounds the wait for a station's REGISTER_ACK: macula's
// 30 seconds, the time a handshake may take.
var registerAckTimeout = 30 * time.Second

// RefusedError is a station's refusal of a registration: the ADVERTISE of a
// procedure or the SUBSCRIBE to a topic (Kind and Name), in Realm, with its
// reason, one section 3.5 names or refused for one this library does not know.
type RefusedError struct {
	Kind    string
	Realm   [32]byte
	Name    string
	Station [32]byte
	Reason  string
}

func (e *RefusedError) Error() string {
	return fmt.Sprintf("stationlink: the station refused the %s of %q: %s", e.Kind, e.Name, e.Reason)
}

// UnacknowledgedError is a registration the station did not answer within
// 30 seconds; the link withdrew it, so a late acceptance does not linger.
type UnacknowledgedError struct {
	Kind    string
	Realm   [32]byte
	Name    string
	Station [32]byte
}

func (e *UnacknowledgedError) Error() string {
	return fmt.Sprintf("stationlink: the station did not acknowledge the %s of %q", e.Kind, e.Name)
}

// registration is what a REGISTER_ACK is matched on.
type registration struct {
	kind       string
	realm      [32]byte
	name       string
	version    [16]byte
	subscriber [32]byte
}

func registrationOfAck(ack frame.RegisterAck) registration {
	r := registration{kind: ack.Kind, realm: ack.Realm, name: ack.Name}
	if ack.Kind == "advertise" || ack.Kind == "unadvertise" {
		r.version = ack.RecordVersion
	} else {
		r.subscriber = ack.Subscriber
	}
	return r
}

// expect registers a wait for r's ack, before its frame is sent so an ack
// that comes back at once is not missed.
func (l *Link) expect(r registration) chan frame.RegisterAck {
	answer := make(chan frame.RegisterAck, 1)
	l.mu.Lock()
	l.awaiting[r] = answer
	l.mu.Unlock()
	return answer
}

func (l *Link) forget(r registration, answer chan frame.RegisterAck) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.awaiting[r] == answer {
		delete(l.awaiting, r)
	}
}

// acknowledged hands an ack to the wait for its registration, and reports
// whether one was waiting.
func (l *Link) acknowledged(ack frame.RegisterAck) bool {
	r := registrationOfAck(ack)
	l.mu.Lock()
	answer, waiting := l.awaiting[r]
	delete(l.awaiting, r)
	l.mu.Unlock()
	if waiting {
		answer <- ack
	}
	return waiting
}

// verdict waits for r's ack: nil when the station accepted it, a
// *RefusedError when it refused, an *UnacknowledgedError when no ack came in
// time, ctx's error when ctx ended first, and the link's when it ended.
func (l *Link) verdict(ctx context.Context, r registration, answer chan frame.RegisterAck) error {
	defer l.forget(r, answer)
	timer := time.NewTimer(registerAckTimeout)
	defer timer.Stop()
	select {
	case ack := <-answer:
		if ack.Accepted {
			return nil
		}
		return &RefusedError{Kind: r.kind, Realm: r.realm, Name: r.name, Station: l.station.NodeID, Reason: ack.Reason}
	case <-timer.C:
		return &UnacknowledgedError{Kind: r.kind, Realm: r.realm, Name: r.name, Station: l.station.NodeID}
	case <-ctx.Done():
		return ctx.Err()
	case <-l.done:
		return l.Err()
	}
}
