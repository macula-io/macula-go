package stationlink

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// heldNow is how many publications a link holds still unconfirmed.
func heldNow(l *Link) int {
	l.unconfirmed.mu.Lock()
	defer l.unconfirmed.mu.Unlock()
	return len(l.unconfirmed.items)
}

// waitingUntil is a deadline a test waits on: f until it answers true, or the
// test fails.
func waitingUntil(t *testing.T, what string, d time.Duration, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

// probing is a link to a station that answers its liveness probes, every 100 ms
// rather than the build's half minute, so a test sees a pong in a fraction of a
// second. The station this package's tests use answers nothing on its own: each
// frame it reads is handed to the test.
func probing(t *testing.T) *Link {
	t.Helper()
	restoreEvery, restoreWait := livenessEvery, livenessTimeout
	livenessEvery, livenessTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { livenessEvery, livenessTimeout = restoreEvery, restoreWait })
	s := startTestStation(t, profile.PQPure, "")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	go func() {
		for raw := range s.received {
			if frameType, nonce, ok := frame.LivenessNonce(decodeFrame(t, raw)); ok && frameType == "liveness_ping" {
				s.send(cbor.Encode(frame.LivenessPongFrame(nonce)))
			}
		}
	}()
	return link
}

// published is a publication signed on the link's own key and seq, as Publish
// signs one.
func published(t *testing.T, link *Link, text string) SignedPublication {
	t.Helper()
	signed, err := SignPublication(link.key, link.seq, Publication{Realm: [32]byte{1}, Topic: "held/wire/x_v1",
		Payload: cbor.Text(text)})
	if err != nil {
		t.Fatalf("SignPublication: %v", err)
	}
	return signed
}

// The pong of a frame sent after a publication proves the station read the
// publication: what was held is let go of, and never sent again.
func TestThePongOfALaterFrameReleasesWhatWasHeld(t *testing.T) {
	link := probing(t)
	if err := link.PublishSigned(published(t, link, "read by the station")); err != nil {
		t.Fatalf("PublishSigned: %v", err)
	}
	waitingUntil(t, "the pong of a later frame releases the publication", 5*time.Second, func() bool {
		return heldNow(link) == 0
	})
}

// A confirmed publication is not sent again when the link ends: the set the
// hand-over takes is what the station has not answered for, and it answered.
func TestAConfirmedPublicationIsNotSentAgainWhenItsLinkEnds(t *testing.T) {
	link := probing(t)
	if err := link.PublishSigned(published(t, link, "read before the end")); err != nil {
		t.Fatalf("PublishSigned: %v", err)
	}
	waitingUntil(t, "the publication is confirmed", 5*time.Second, func() bool { return heldNow(link) == 0 })
	EndLink(link, ErrClosed)
	if held := link.TakeUnconfirmed(); len(held) != 0 {
		t.Errorf("a confirmed publication is in the hand-over after the link ended: %d held", len(held))
	}
}
