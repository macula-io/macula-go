package stationlink

import (
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 handshake on the link (macula docs/design/WIRE_1_0.md section 4): version 5 alone, never below the
// floor this process keeps per station. No frame carries a neighbour signature and the liveness probe is
// liveness_ping, answered by the other end's connection.

func counted(name string, before map[string]uint64) uint64 {
	return HandshakeCounters()[name] - before[name]
}

func TestALinkConnectsOnVersion5AndSignsNoFrame(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			before := HandshakeCounters()
			s := startTestStationAs(t, p, "wire 1.0 station "+string(p))
			link, err := dial(t, s, newClient(t, p))
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			s.waitAccepted()
			if link.HandshakeVersion() != 5 || s.client.Version != 5 {
				t.Fatalf("versions: link %d, station %d, want 5", link.HandshakeVersion(), s.client.Version)
			}
			if counted("connections", before) != 1 {
				t.Errorf("counters %v, want one connection", HandshakeCounters())
			}
			if floors.of(s.nodeID) != 5 {
				t.Errorf("the floor for the station is %d, want 5 once a handshake completed", floors.of(s.nodeID))
			}
			if err := link.Close("client_stop"); err != nil {
				t.Fatalf("Close: %v", err)
			}
			goodbye, err := frame.ReadControl(decodeFrame(t, s.next()))
			if err != nil {
				t.Fatalf("the GOODBYE: %v", err)
			}
			if reason, _ := frameField(goodbye, "reason").AsText(); reason != "client_stop" {
				t.Errorf("GOODBYE reason %q", reason)
			}
		})
	}
}

// The link answers the station's liveness_ping with a liveness_pong of the same nonce, and hands neither on.
func TestALinkAnswersTheStationsLivenessPing(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "liveness station")
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

// The link probes the station with liveness_ping: answered, it stays up; unanswered twice, it ends.
func TestALinkProbesWithLivenessPing(t *testing.T) {
	restoreEvery, restoreWait := livenessEvery, livenessTimeout
	livenessEvery, livenessTimeout = 100*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { livenessEvery, livenessTimeout = restoreEvery, restoreWait })
	s := startTestStationAs(t, profile.PQPure, "probed station")
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

// A link never completes below the floor this process keeps for a station: a challenge choosing a version
// below it is refused as version_below_floor before the client signs anything, and counted.
func TestALinkRefusesAStationBelowItsFloor(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "floored station")
	floors.mu.Lock()
	floors.floor[s.nodeID] = 6
	floors.mu.Unlock()
	t.Cleanup(func() {
		floors.mu.Lock()
		delete(floors.floor, s.nodeID)
		floors.mu.Unlock()
	})
	before := HandshakeCounters()
	if _, err := dial(t, s, newClient(t, profile.PQPure)); !errors.Is(err, handshake.ErrVersionBelowFloor) {
		t.Fatalf("Dial: %v, want ErrVersionBelowFloor", err)
	}
	if counted("version_below_floor", before) != 1 {
		t.Errorf("counters %v, want one version_below_floor", HandshakeCounters())
	}
}

// A station keeps a floor per client too: one whose floor for this client is above 5 refuses the CONNECT, and the
// client reads the coarse not_accepted.
func TestAStationBelowWhoseFloorTheClientIsRefusesIt(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "station with a floor")
	s.mu.Lock()
	s.floor = func([32]byte) int64 { return 6 }
	s.mu.Unlock()
	_, err := dial(t, s, newClient(t, profile.PQPure))
	var refused *handshake.RefusedError
	if !errors.As(err, &refused) || refused.Code != handshake.RefusalNotAccepted {
		t.Fatalf("Dial: %v, want a refusal with not_accepted", err)
	}
}
