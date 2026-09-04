package pool

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// linkEvent is what a link posts to the coordinator's own inbox on a
// lifecycle transition — never a direct callback into coordinator state,
// since a link's supervise loop runs on its own goroutine and
// coordinator state (topic index, procs, dedup) must only ever be
// touched by the coordinator's single goroutine. Mirrors
// macula_client.erl's own DOWN/respawn handling, which the SAME
// single gen_server process handles because Erlang's monitor message
// already lands in that process's mailbox for free; Go needs this
// explicit channel to get the same single-writer property.
type linkEvent struct {
	link  *link
	actor *actor // set when up == true
	up    bool
	err   error // set when up == false
}

// link supervises ONE seed or direct-dial target: dial, run its actor
// until the session dies, back off, redial — for as long as ctx lives.
// One physical Session per link, ever (never two concurrent connections
// to the same target) — see pool.go's own doc on why: a station kicks a
// duplicate connection under the same identity, confirmed against
// macula_station_listener.erl and against a bug macula_client.erl itself
// hit and fixed the same way (reuse, never double-dial).
type link struct {
	key   string // host:port, net.JoinHostPort form -- the map key everywhere
	host  string
	port  uint16
	trust transport.Trust // persists across every respawn -- see pool.go's own doc on the Erlang bug this avoids repeating
	id    identity.KeyPair
	dial  dialFunc

	livenessInterval  time.Duration
	livenessMaxMisses int

	backoff time.Duration
	events  chan<- inboundEvent
	notify  chan<- linkEvent

	mu    sync.Mutex
	actor *actor
}

func newLink(host string, port uint16, trust transport.Trust, id identity.KeyPair, dial dialFunc, backoff, livenessInterval time.Duration, livenessMaxMisses int, events chan<- inboundEvent, notify chan<- linkEvent) *link {
	return &link{
		key: linkKey(host, port), host: host, port: port, trust: trust, id: id,
		dial: dial, backoff: backoff,
		livenessInterval: livenessInterval, livenessMaxMisses: livenessMaxMisses,
		events: events, notify: notify,
	}
}

// supervise blocks until ctx is done, dialing, running, and (on death)
// backing off and redialing this link's target for as long as ctx lives.
// Run this in its own goroutine, one per link — different links must
// dial/back off independently.
func (l *link) supervise(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		dr, err := l.dial(ctx, l.host, l.port, l.trust, l.id)
		if err != nil {
			if !sleepOrDone(ctx, l.backoff) {
				return
			}
			continue
		}

		// dr.nodeID (the peer's identity, read synchronously off the
		// already-verified HELLO) is not yet consulted for reuse -- see
		// CallStation's own doc on the gap this would close.
		a := newActor(l.key, dr.session, l.id, l.events, l.livenessInterval, l.livenessMaxMisses)
		l.mu.Lock()
		l.actor = a
		l.mu.Unlock()

		select {
		case l.notify <- linkEvent{link: l, actor: a, up: true}:
		case <-ctx.Done():
			l.mu.Lock()
			l.actor = nil
			l.mu.Unlock()
			return
		}

		runErr := a.run(ctx)

		l.mu.Lock()
		l.actor = nil
		l.mu.Unlock()

		select {
		case l.notify <- linkEvent{link: l, up: false, err: runErr}:
		case <-ctx.Done():
			return
		}

		if !sleepOrDone(ctx, l.backoff) {
			return
		}
	}
}

// CurrentActor returns this link's live actor, or nil if it's currently
// dialing/backing off. Safe from any goroutine.
func (l *link) CurrentActor() *actor {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.actor
}

func linkKey(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-time.After(d):
		return true
	case <-ctx.Done():
		return false
	}
}
