package connection

import (
	"bytes"
	"testing"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// handshaked is a session as the registry sees it: the identity it connected
// as, the station it reached, and a done channel the returned end func closes
// to end its connection. The test registers it itself.
func handshaked(t *testing.T, id identity.KeyPair, station []byte) (*Session, func()) {
	t.Helper()
	done := make(chan struct{})
	s := &Session{Station: frame.HelloInfo{NodeID: station}, identity: id.NodeID(), done: done}
	end := func() {
		select {
		case <-done:
		default:
			close(done)
		}
	}
	t.Cleanup(func() {
		unregister(s)
		end()
	})
	return s, end
}

func registryIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func stationNode(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func TestASessionIsFoundByItsIdentityAndStation(t *testing.T) {
	id, other := registryIdentity(t), registryIdentity(t)
	s, _ := handshaked(t, id, stationNode(1))
	register(s)

	if got, ok := registeredSession(id, stationNode(1)); !ok || got != s {
		t.Fatalf("registeredSession(id, station 1) = %p, %v; want the registered session %p", got, ok, s)
	}
	if _, ok := registeredSession(id, stationNode(2)); ok {
		t.Fatal("SessionFor found a session for a station this identity never reached")
	}
	if _, ok := registeredSession(other, stationNode(1)); ok {
		t.Fatal("SessionFor found a session for an identity that never connected")
	}
}

func TestTheNewestSessionPerIdentityAndStationWins(t *testing.T) {
	id := registryIdentity(t)
	older, _ := handshaked(t, id, stationNode(1))
	newer, _ := handshaked(t, id, stationNode(1))
	register(older)
	register(newer)

	if got, ok := registeredSession(id, stationNode(1)); !ok || got != newer {
		t.Fatalf("SessionFor = %p, %v; want the newer session %p", got, ok, newer)
	}
}

// Close unregisters a session; unregistering the older of two sessions for
// the same identity and station must not drop the newer one.
func TestClosingAnOlderSessionLeavesTheNewerOneRegistered(t *testing.T) {
	id := registryIdentity(t)
	older, _ := handshaked(t, id, stationNode(1))
	newer, _ := handshaked(t, id, stationNode(1))
	register(older)
	register(newer)
	unregister(older)

	if got, ok := registeredSession(id, stationNode(1)); !ok || got != newer {
		t.Fatalf("SessionFor = %p, %v; want the newer session %p", got, ok, newer)
	}
}

func TestAClosedSessionIsNoLongerFound(t *testing.T) {
	id := registryIdentity(t)
	s, _ := handshaked(t, id, stationNode(1))
	register(s)
	unregister(s)

	if _, ok := registeredSession(id, stationNode(1)); ok {
		t.Fatal("SessionFor found a session that was closed")
	}
}

// A session whose connection ended without Close, such as one the station
// dropped, is not offered for reuse, and the registry forgets it.
func TestASessionWhoseConnectionEndsIsNoLongerFoundForReuse(t *testing.T) {
	id := registryIdentity(t)
	s, end := handshaked(t, id, stationNode(1))
	register(s)
	end()

	if _, ok := registeredSession(id, stationNode(1)); ok {
		t.Fatal("SessionFor found a session whose connection ended")
	}
	deadline := time.Now().Add(2 * time.Second)
	for registered(id, stationNode(1)) {
		if time.Now().After(deadline) {
			t.Fatal("the registry still holds a session whose connection ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// registered reports whether the registry holds an entry for id and station.
func registered(id identity.KeyPair, station []byte) bool {
	openSessions.Lock()
	defer openSessions.Unlock()
	_, ok := openSessions.byKey[sessionKey{identity: string(id.NodeID()), station: string(station)}]
	return ok
}
