package pool

import (
	"context"
	"sync"
	"time"

	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

// member is one station the pool links to, a seed of either tier or a station
// dialed directly for a call: it dials the station, and when the link ends
// dials it again on the pool's respawn plan, until the pool closes.
type member struct {
	pool   *Pool
	target transport.Target
	// direct marks a station dialled for a call rather than named by the
	// caller; its tier is public.
	direct bool
	tier   Tier
	done   chan struct{}
	ctx    context.Context
	retire context.CancelFunc

	// wake re-arms a parked retry: the pool sends on it, at most one waiting,
	// when this member's tier becomes the active one (macula#201 §3).
	wake chan struct{}

	mu   sync.Mutex
	link *stationlink.Link
	err  error
	// parked is set while the member waits out a retry. A re-arm restarts the
	// retries that are pending, and a member that is dialing or up has none.
	parked bool
	// attempts is how many backoff retries this station has taken, cleared by
	// a steady-up or by a re-arm. The active tier's flat delay counts nothing.
	attempts int
	// up is closed, and replaced, each time a link comes up; failed each
	// time a dial fails.
	up     chan struct{}
	failed chan struct{}
}

func (p *Pool) startMember(target transport.Target, direct bool, tier Tier) *member {
	ctx, retire := context.WithCancel(p.ctx)
	m := &member{pool: p, target: target, direct: direct, tier: tier, done: make(chan struct{}),
		wake: make(chan struct{}, 1), up: make(chan struct{}), failed: make(chan struct{}), ctx: ctx, retire: retire}
	p.mu.Lock()
	p.members = append(p.members, m)
	p.mu.Unlock()
	go m.supervise()
	return m
}

func (m *member) current() *stationlink.Link {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.link
}

func (m *member) lastErr() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.err
}

// awaitUp is the member's link once it is up, or nil when ctx ends first or,
// with failFast, when its next dial fails.
func (m *member) awaitUp(ctx context.Context, failFast bool) *stationlink.Link {
	for {
		m.mu.Lock()
		link, up, failed := m.link, m.up, m.failed
		m.mu.Unlock()
		if link != nil {
			return link
		}
		if !failFast {
			failed = nil
		}
		select {
		case <-up:
		case <-failed:
			return nil
		case <-ctx.Done():
			return nil
		case <-m.done:
			return nil
		}
	}
}

func (m *member) supervise() {
	for {
		if link, err := m.dial(); err != nil {
			m.failedDial(err)
		} else {
			m.linked(link)
		}
		if !m.pause() {
			close(m.done)
			return
		}
	}
}

// failedDial records a dial that did not come up, and tells the pool.
func (m *member) failedDial(err error) {
	m.mu.Lock()
	m.err = err
	close(m.failed)
	m.failed = make(chan struct{})
	m.mu.Unlock()
	m.pool.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Err: err})
}

// linked holds the member's new link until it ends or the pool closes, then
// records how it ended.
func (m *member) linked(link *stationlink.Link) {
	m.cameUp(link)
	select {
	case <-link.Done():
	case <-m.ctx.Done():
		_ = link.Close("client_stop")
	}
	m.wentDown(link)
}

// cameUp takes the member's new link and tells the pool, which may have just
// moved onto this member's tier.
func (m *member) cameUp(link *stationlink.Link) {
	before := m.pool.ActiveTier()
	m.mu.Lock()
	m.link, m.err = link, nil
	close(m.up)
	m.up = make(chan struct{})
	m.mu.Unlock()
	m.pool.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Up: true})
	m.armSteadyUp(link)
	m.pool.replay(link)
	m.pool.noticeTier(before)
}

// wentDown records the end of the member's link and tells the pool, which may
// have just left this member's tier.
func (m *member) wentDown(link *stationlink.Link) {
	before := m.pool.ActiveTier()
	m.mu.Lock()
	m.link, m.err = nil, link.Err()
	m.mu.Unlock()
	m.pool.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Err: link.Err()})
	m.pool.noticeTier(before)
}

// armSteadyUp clears the member's backoff once its link has stayed up the
// steady-up window. The timer names the link that completed the handshake: a
// link that connects and dies before the window elapses leaves a timer that
// clears nothing, so a connect-then-die loop keeps the backoff it accumulated.
func (m *member) armSteadyUp(link *stationlink.Link) {
	time.AfterFunc(m.pool.opts.Redial.SteadyUp, func() {
		if m.current() != link {
			return
		}
		m.mu.Lock()
		m.attempts = 0
		m.mu.Unlock()
	})
}

// pause waits out the member's retry, and reports whether it should dial again,
// false when the pool closed first. A re-arm wakes a parked retry: the wait then
// starts again from the redial base.
func (m *member) pause() bool {
	m.mu.Lock()
	m.parked = true
	attempt := m.attempts
	m.mu.Unlock()
	wait, counted := m.pool.respawnPlan(m.tier, attempt)
	if counted {
		m.mu.Lock()
		m.attempts++
		m.mu.Unlock()
	}
	defer m.unpark()
	for {
		timer := time.NewTimer(wait)
		select {
		case <-m.ctx.Done():
			timer.Stop()
			return false
		case <-m.wake:
			timer.Stop()
			wait = m.pool.opts.Redial.wait(0)
		case <-timer.C:
			return true
		}
	}
}

func (m *member) unpark() {
	m.mu.Lock()
	m.parked = false
	m.mu.Unlock()
}

// rearm restarts a parked retry from the redial base with its count cleared.
// A member that is dialing or up has no pending retry to restart, and is left
// with the count it earned.
func (m *member) rearm() {
	m.mu.Lock()
	parked := m.parked
	if parked {
		m.attempts = 0
	}
	m.mu.Unlock()
	if !parked {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *member) dial() (*stationlink.Link, error) {
	ctx, cancel := context.WithTimeout(m.ctx, stationlink.HandshakeTimeout)
	defer cancel()
	cfg := m.pool.shared
	cfg.Target = m.target
	return stationlink.Dial(ctx, cfg)
}

// stop waits for the member's link to close with the pool.
func (m *member) stop() {
	<-m.done
}

// drop retires a member the pool no longer keeps: its link closes, it is not
// dialed again, and it leaves the pool's members.
func (p *Pool) drop(m *member) {
	m.retire()
	p.mu.Lock()
	for i, held := range p.members {
		if held == m {
			p.members = append(p.members[:i], p.members[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

// replay gives a new link the node's subscriptions, then its served
// procedures, as macula's pool replays them on a respawned link.
func (p *Pool) replay(link *stationlink.Link) {
	p.mu.Lock()
	subs := make([]*Subscription, 0, len(p.subs))
	for sub := range p.subs {
		subs = append(subs, sub)
	}
	served := make([]*Served, 0, len(p.served))
	for s := range p.served {
		served = append(served, s)
	}
	p.mu.Unlock()
	for _, sub := range subs {
		go func() { _ = sub.attach(link) }()
	}
	for _, s := range served {
		s.attach(link)
	}
}
