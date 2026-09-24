package pool

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/macula-io/macula-go/stationlink"
)

// ErrNoRealmKey is a realm the pool pins no key for: nothing in it can be
// served or trusted.
var ErrNoRealmKey = errors.New("pool: no realm key pinned for the realm")

// Offer is a procedure the node serves: its realm, which the pool must pin a
// key for, its name, its handler, and whether it is gated (refused until
// macula-go has a post-quantum UCAN verifier).
type Offer struct {
	Realm     [32]byte
	Procedure string
	Handler   stationlink.Handler
	Gated     bool
}

// Served is a procedure the node serves on every link the pool holds, and on
// every link it dials later, until Stop.
type Served struct {
	pool  *Pool
	offer stationlink.Offer

	mu      sync.Mutex
	onLinks map[*stationlink.Link]*stationlink.Served
	stopped bool
}

// Serve serves o on every link that is up, and on every link that comes up
// after. It succeeds when one link serves it; each link advertises it naming
// its own station, and renews and puts it in the DHT as stationlink.Serve
// does.
func (p *Pool) Serve(ctx context.Context, o Offer) (*Served, error) {
	realmKey, pinned := p.opts.RealmTrust[o.Realm]
	if !pinned {
		return nil, ErrNoRealmKey
	}
	if o.Gated {
		return nil, stationlink.ErrGatedUnsupported
	}
	s := &Served{pool: p, onLinks: map[*stationlink.Link]*stationlink.Served{},
		offer: stationlink.Offer{Realm: o.Realm, Procedure: o.Procedure, Handler: o.Handler, RealmKey: realmKey}}
	links := p.links()
	if len(links) == 0 {
		return nil, ErrNoLink
	}
	var errs []error
	for _, link := range links {
		if err := s.serveOn(ctx, link); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) == len(links) {
		return nil, errors.Join(errs...)
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	p.served[s] = struct{}{}
	p.mu.Unlock()
	for _, link := range p.links() {
		s.attach(link)
	}
	return s, nil
}

// serveOn serves the offer on link, once, and serves it again after
// RespawnDelay when it lapses while the link lives.
func (s *Served) serveOn(ctx context.Context, link *stationlink.Link) error {
	s.mu.Lock()
	if s.stopped || s.onLinks[link] != nil {
		s.mu.Unlock()
		return nil
	}
	s.mu.Unlock()
	onLink, err := link.Serve(ctx, s.offer)
	if errors.Is(err, stationlink.ErrAlreadyServed) {
		return nil
	}
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return onLink.Stop()
	}
	s.onLinks[link] = onLink
	s.mu.Unlock()
	go s.watch(link, onLink)
	return nil
}

// attach serves the offer on a link the pool dialed, retrying every
// RespawnDelay while the link lives and the offer is not served there.
func (s *Served) attach(link *stationlink.Link) {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(s.pool.ctx, stationlink.DefaultCallTimeout)
			err := s.serveOn(ctx, link)
			cancel()
			if err == nil {
				return
			}
			select {
			case <-link.Done():
				return
			case <-s.pool.ctx.Done():
				return
			case <-time.After(s.pool.opts.RespawnDelay):
			}
		}
	}()
}

// watch forgets a link's serving when it ends, and serves the offer there
// again when it lapsed while the link lives.
func (s *Served) watch(link *stationlink.Link, onLink *stationlink.Served) {
	<-onLink.Done()
	s.mu.Lock()
	if s.onLinks != nil && s.onLinks[link] == onLink {
		delete(s.onLinks, link)
	}
	stopped := s.stopped
	s.mu.Unlock()
	if stopped || errors.Is(onLink.Err(), stationlink.ErrStopped) {
		return
	}
	select {
	case <-link.Done():
	case <-s.pool.ctx.Done():
	case <-time.After(s.pool.opts.RespawnDelay):
		s.attach(link)
	}
}

// Stop withdraws the procedure on every link.
func (s *Served) Stop() error {
	s.pool.mu.Lock()
	delete(s.pool.served, s)
	s.pool.mu.Unlock()
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return nil
	}
	s.stopped = true
	onLinks := s.onLinks
	s.onLinks = nil
	s.mu.Unlock()
	var errs []error
	for _, onLink := range onLinks {
		if err := onLink.Stop(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
