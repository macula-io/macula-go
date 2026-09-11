package connection

import (
	"context"
	"sync"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// Lease is one hold on a session for work that doesn't own it, such as a
// direct dial. Acquire leases a session this process already holds;
// DialLeased opens a session for the work. Release gives the hold back. A
// session DialLeased opened closes when its last lease is released; a
// session opened any other way is never closed by a lease.
type Lease struct {
	session *Session
	once    sync.Once
}

// Session is the leased session.
func (l *Lease) Session() *Session { return l.session }

// Release gives the hold back. Releasing the same lease again does nothing.
func (l *Lease) Release() {
	l.once.Do(func() { l.session.leases.release() })
}

// leases counts the holds on a session DialLeased opened. When the count
// reaches zero the session is closing and takes no new lease. A nil *leases
// belongs to a session the application opened: taking a lease always
// succeeds and releasing one never closes it.
type leases struct {
	mu      sync.Mutex
	held    int
	closing bool
	close   func()
}

func (ls *leases) take() bool {
	if ls == nil {
		return true
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.closing {
		return false
	}
	ls.held++
	return true
}

func (ls *leases) release() {
	if ls == nil {
		return
	}
	ls.mu.Lock()
	ls.held--
	last := ls.held == 0
	if last {
		ls.closing = true
	}
	ls.mu.Unlock()
	if last {
		ls.close()
	}
}

// Acquire leases the session this process holds to station under id, if
// there is one whose connection is up and that isn't closing.
func Acquire(id identity.KeyPair, station []byte) (*Lease, bool) {
	s, ok := registeredSession(id, station)
	if !ok || !s.leases.take() {
		return nil, false
	}
	return &Lease{session: s}, true
}

// DialLeased connects to host:port as Connect does and returns the new
// session with one lease held on it, so it closes when its last lease is
// released. It becomes leasable by Acquire only with that first lease held.
func DialLeased(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (*Lease, error) {
	s, err := connectOne(ctx, host, port, trust, id, true)
	if err != nil {
		return nil, err
	}
	return &Lease{session: s}, nil
}
