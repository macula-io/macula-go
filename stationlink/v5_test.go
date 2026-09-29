package stationlink

import (
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// Handshake v5 on the link (macula plans/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md sections 3 and 4): a link dials v5,
// falls back to v4 once, only after unsupported_version, from a station never seen on v5, and refuses a station
// seen on v5 that answers v4 until ForgetV5Peer. On v5 no frame carries a neighbour signature and the liveness
// probe is liveness_ping, answered by the other end's connection.

func counted(name string, before map[string]uint64) uint64 {
	return HandshakeCounters()[name] - before[name]
}

func TestALinkToAV5StationConnectsOnV5AndSignsNoFrame(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			before := HandshakeCounters()
			s := startTestStationV5(t, p, "v5 station "+string(p))
			link, err := dial(t, s, newClient(t, p))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			s.waitAccepted()
			if link.HandshakeVersion() != 5 || s.client.Version != 5 {
				t.Fatalf("versions: link %d, station %d, want 5", link.HandshakeVersion(), s.client.Version)
			}
			if counted("v5_connections", before) != 1 || counted("v4_fallbacks", before) != 0 {
				t.Errorf("counters %v, want one v5 connection and no fallback", HandshakeCounters())
			}
			if err := link.Close("client_stop"); err != nil {
				t.Fatalf("Close: %v", err)
			}
			goodbye, err := frame.VerifySessionFrame(decodeFrame(t, s.next()))
			if err != nil {
				t.Fatalf("the GOODBYE on v5: %v", err)
			}
			if reason, _ := frameField(goodbye, "reason").AsText(); reason != "client_stop" {
				t.Errorf("GOODBYE reason %q", reason)
			}
		})
	}
}

// On v5 the station's unsigned GOODBYE ends the link with its reason; a neighbour-signed one ends it as malformed.
func TestAV5LinkReadsFramesWithoutNeighbourSignatures(t *testing.T) {
	for _, signed := range []bool{false, true} {
		s := startTestStationV5(t, profile.PQHybrid, "v5 goodbye station")
		link, err := dial(t, s, newClient(t, profile.PQHybrid))
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		s.waitAccepted()
		goodbye, err := frame.GoodbyeFrame("normal", nil)
		if err != nil {
			t.Fatal(err)
		}
		if signed {
			if goodbye, err = frame.SignNeighbour(goodbye, s.key, frame.NeighbourLink{Connection: s.connection}); err != nil {
				t.Fatal(err)
			}
		}
		s.send(cbor.Encode(goodbye))
		err = waitDone(t, link)
		var bye *GoodbyeError
		switch {
		case !signed && !(errors.As(err, &bye) && bye.Reason == "normal"):
			t.Errorf("an unsigned GOODBYE on v5 ended the link with %v, want the station's goodbye", err)
		case signed && !errors.Is(err, frame.ErrMalformedFrame):
			t.Errorf("a neighbour-signed GOODBYE on v5 ended the link with %v, want ErrMalformedFrame", err)
		}
	}
}

// The link answers the station's liveness_ping with a liveness_pong of the same nonce, and hands neither on.
func TestAV5LinkAnswersTheStationsLivenessPing(t *testing.T) {
	s := startTestStationV5(t, profile.PQPure, "v5 liveness station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	nonce := [16]byte{9, 9}
	s.send(cbor.Encode(frame.LivenessPingFrame(nonce)))
	frameType, got, ok := frame.LivenessNonce(decodeFrame(t, s.next()))
	if !ok || frameType != "liveness_pong" || got != nonce {
		t.Errorf("the answer: (%q, %x, %t), want a liveness_pong with the ping's nonce", frameType, got, ok)
	}
	if link.Unrouted()["liveness_ping"] != 0 {
		t.Errorf("unrouted %v: the liveness frame was handed on", link.Unrouted())
	}
}

// The link probes a v5 station with liveness_ping: answered, it stays up; unanswered twice, it ends.
func TestAV5LinkProbesWithLivenessPing(t *testing.T) {
	restoreEvery, restoreWait := livenessEvery, livenessTimeout
	livenessEvery, livenessTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { livenessEvery, livenessTimeout = restoreEvery, restoreWait })
	s := startTestStationV5(t, profile.PQPure, "v5 probed station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	answering := make(chan bool, 1)
	answering <- true
	go func() {
		for raw := range s.received {
			frameType, nonce, ok := frame.LivenessNonce(decodeFrame(t, raw))
			on := <-answering
			answering <- on
			if ok && frameType == "liveness_ping" && on {
				s.send(cbor.Encode(frame.LivenessPongFrame(nonce)))
			}
		}
	}()
	select {
	case <-link.Done():
		t.Fatalf("the link ended while the station answered: %v", link.Err())
	case <-time.After(600 * time.Millisecond):
	}
	<-answering
	answering <- false
	if err := waitDone(t, link); !errors.Is(err, ErrLivenessLost) {
		t.Errorf("the link ended with %v, want ErrLivenessLost", err)
	}
}

// A pre-v5 station refuses the v5 CONNECT with unsupported_version; the link dials it once more, with v4, and
// connects on v4; the station saw one refused handshake.
func TestALinkFallsBackOnceToAPreV5Station(t *testing.T) {
	before := HandshakeCounters()
	s := startStation(t, profile.PQPure, "pre-v5 station", false, "")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	if link.HandshakeVersion() != 4 || s.refused != 1 {
		t.Errorf("version %d after %d refused handshakes, want v4 after one", link.HandshakeVersion(), s.refused)
	}
	if counted("v4_fallbacks", before) != 1 || counted("v4_connections", before) != 1 {
		t.Errorf("counters %v, want one fallback and one v4 connection", HandshakeCounters())
	}
	// Within 10 minutes the next dial to that node goes straight to v4.
	again := startStation(t, profile.PQPure, "pre-v5 station", false, "")
	if _, err := dial(t, again, newClient(t, profile.PQPure)); err != nil || again.refused != 0 {
		t.Errorf("the next dial: %v after %d refused handshakes, want v4 directly", err, again.refused)
	}
}

// A station seen on v5 that answers v4 is refused as a downgrade, with no second dial; once forgotten, the link
// falls back and connects on v4.
func TestAStationSeenOnV5ThatAnswersV4IsRefusedUntilForgotten(t *testing.T) {
	keyName := "rolled-back station"
	v5 := startTestStationV5(t, profile.PQPure, keyName)
	if _, err := dial(t, v5, newClient(t, profile.PQPure)); err != nil {
		t.Fatalf("Dial v5: %v", err)
	}
	before := HandshakeCounters()
	rolledBack := startStation(t, profile.PQPure, keyName, false, "")
	if _, err := dial(t, rolledBack, newClient(t, profile.PQPure)); !errors.Is(err, ErrV5DowngradeRefused) {
		t.Fatalf("Dial to the rolled-back station: %v, want ErrV5DowngradeRefused", err)
	}
	if counted("v5_downgrade_refused", before) != 1 || counted("v4_fallbacks", before) != 0 {
		t.Errorf("counters %v, want one refused downgrade and no fallback", HandshakeCounters())
	}
	ForgetV5Peer(rolledBack.nodeID)
	forgiven := startStation(t, profile.PQPure, keyName, false, "")
	link, err := dial(t, forgiven, newClient(t, profile.PQPure))
	if err != nil || link.HandshakeVersion() != 4 {
		t.Errorf("after ForgetV5Peer: %v, version %d, want a v4 link", err, link.HandshakeVersion())
	}
}

// On a v4 link the liveness frames do not exist: one ends the link as malformed.
func TestAV4LinkRefusesLivenessFrames(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	if link.HandshakeVersion() != 4 {
		t.Fatalf("the pre-v5 station's link is version %d", link.HandshakeVersion())
	}
	s.send(cbor.Encode(frame.LivenessPingFrame([16]byte{1})))
	if err := waitDone(t, link); !errors.Is(err, frame.ErrMalformedFrame) {
		t.Errorf("a liveness_ping on v4 ended the link with %v, want ErrMalformedFrame", err)
	}
}
