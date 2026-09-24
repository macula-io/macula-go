package pool

import (
	"context"
	"sync"
	"time"

	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

// member is one station the pool links to, a seed or a station dialed
// directly for a call: it dials the station, and when the link ends dials it
// again after RespawnDelay, until the pool closes.
type member struct {
	pool   *Pool
	target transport.Target
	direct bool
	done   chan struct{}
	ctx    context.Context
	retire context.CancelFunc

	mu   sync.Mutex
	link *stationlink.Link
	err  error
	// up is closed, and replaced, each time a link comes up; failed each
	// time a dial fails.
	up     chan struct{}
	failed chan struct{}
}

func (p *Pool) startMember(target transport.Target, direct bool) *member {
	ctx, retire := context.WithCancel(p.ctx)
	m := &member{pool: p, target: target, direct: direct, done: make(chan struct{}), up: make(chan struct{}),
		failed: make(chan struct{}), ctx: ctx, retire: retire}
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
	p := m.pool
	for {
		link, err := m.dial()
		if err != nil {
			m.mu.Lock()
			m.err = err
			close(m.failed)
			m.failed = make(chan struct{})
			m.mu.Unlock()
			p.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Err: err})
		} else {
			m.mu.Lock()
			m.link, m.err = link, nil
			close(m.up)
			m.up = make(chan struct{})
			m.mu.Unlock()
			p.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Up: true})
			p.replay(link)
			select {
			case <-link.Done():
			case <-m.ctx.Done():
				_ = link.Close("client_stop")
			}
			m.mu.Lock()
			m.link, m.err = nil, link.Err()
			m.mu.Unlock()
			p.event(LinkEvent{Station: m.target.ExpectedNodeID, Direct: m.direct, Err: link.Err()})
		}
		select {
		case <-m.ctx.Done():
			close(m.done)
			return
		case <-time.After(p.opts.RespawnDelay):
		}
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
		sub.attach(link)
	}
	for _, s := range served {
		s.attach(link)
	}
}
