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
	link    *link
	session *linkSession // set when up == true
	up      bool
	err     error // set when up == false
}

// link supervises ONE seed or direct-dial target: dial, run its session
// until it ends, back off, redial — for as long as ctx lives.
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

	mu         sync.Mutex
	session    *linkSession
	peerNodeID []byte // updated on every successful dial (a redial can legitimately prove a different node id, e.g. a DNS name repointed); kept across a later respawn/backoff in between, never cleared -- see PeerNodeID's own doc
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
			select {
			case l.notify <- linkEvent{link: l, up: false, err: err}:
			case <-ctx.Done():
				return
			}
			if !sleepOrDone(ctx, l.backoff) {
				return
			}
			continue
		}

		ls := newLinkSession(l.key, dr.session, l.id, l.events, l.livenessInterval, l.livenessMaxMisses)
		l.mu.Lock()
		l.session = ls
		if len(dr.nodeID) > 0 {
			l.peerNodeID = dr.nodeID
		}
		l.mu.Unlock()

		select {
		case l.notify <- linkEvent{link: l, session: ls, up: true}:
		case <-ctx.Done():
			l.mu.Lock()
			l.session = nil
			l.mu.Unlock()
			_ = dr.session.Close("pool: link closing", nil, l.id)
			return
		}

		runErr := ls.run(ctx)

		l.mu.Lock()
		l.session = nil
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

// CurrentSession returns this link's live session, or nil while it is
// dialing or backing off. Safe from any goroutine.
func (l *link) CurrentSession() *linkSession {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.session
}

// PeerNodeID returns the last node id this link's target proved at
// handshake, or nil if it has never dialed successfully even once.
// Deliberately NOT cleared when a session ends (unlike CurrentSession) --
// a link mid-backoff/redial is still, as far as anyone dealing in
// station identity is concerned, "the same station we already have a
// link to," which is exactly what station-discovery's own dedupe-by-
// node-id needs to keep being true through a respawn, not just while a
// session happens to be live. Safe from any goroutine.
func (l *link) PeerNodeID() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.peerNodeID
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
