package connection

import (
	"sync/atomic"
	"testing"

	"github.com/macula-io/macula-go/identity"
)

// leasedSession is a registered session as DialLeased leaves it, with one
// lease held. Its close only counts, so the test can see when a release
// would close the connection.
func leasedSession(t *testing.T, id identity.KeyPair, station []byte) (*Session, *Lease, *atomic.Int32) {
	t.Helper()
	s, _ := handshaked(t, id, station)
	closes := &atomic.Int32{}
	s.leases = &leases{held: 1, close: func() { closes.Add(1) }}
	register(s)
	return s, &Lease{session: s}, closes
}

func TestADialedSessionStaysOpenUntilItsLastLeaseIsReleased(t *testing.T) {
	id := registryIdentity(t)
	s, first, closes := leasedSession(t, id, stationNode(1))
	second, ok := Acquire(id, stationNode(1))
	if !ok || second.Session() != s {
		t.Fatalf("Acquire = %v, %v; want a lease on the dialed session", second, ok)
	}

	first.Release()
	if n := closes.Load(); n != 0 {
		t.Fatalf("the session closed %d time(s) while a lease was still held", n)
	}
	second.Release()
	if n := closes.Load(); n != 1 {
		t.Fatalf("the session closed %d time(s) after its last lease was released, want 1", n)
	}
}

func TestASessionThatIsClosingIsNotReused(t *testing.T) {
	id := registryIdentity(t)
	_, lease, _ := leasedSession(t, id, stationNode(1))
	lease.Release()

	if _, ok := Acquire(id, stationNode(1)); ok {
		t.Fatal("Acquire leased a session whose last lease was released")
	}
}

func TestAnApplicationSessionIsNeverClosedByALease(t *testing.T) {
	id := registryIdentity(t)
	s, _ := handshaked(t, id, stationNode(1))
	register(s)

	lease, ok := Acquire(id, stationNode(1))
	if !ok || lease.Session() != s {
		t.Fatalf("Acquire = %v, %v; want a lease on the application's session", lease, ok)
	}
	lease.Release()
	if again, ok := Acquire(id, stationNode(1)); !ok || again.Session() != s {
		t.Fatal("the application's session was no longer leasable after a lease on it was released")
	}
}

func TestReleasingALeaseTwiceReleasesItOnce(t *testing.T) {
	id := registryIdentity(t)
	_, first, closes := leasedSession(t, id, stationNode(1))
	second, ok := Acquire(id, stationNode(1))
	if !ok {
		t.Fatal("Acquire found no session")
	}

	first.Release()
	first.Release()
	if n := closes.Load(); n != 0 {
		t.Fatalf("releasing one lease twice closed the session %d time(s) while another lease was held", n)
	}
	second.Release()
	if n := closes.Load(); n != 1 {
		t.Fatalf("the session closed %d time(s) after its last lease was released, want 1", n)
	}
}
