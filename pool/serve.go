package pool

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/ucan"
)

// realmKeyFor is the key procedure's authorization is checked against: the
// realm's pinned key, or none for a procedure in a node's own namespace,
// which its advertisement's signature alone authorizes. An org procedure in a
// realm with no pinned key is ErrNoRealmKey.
func (p *Pool) realmKeyFor(realm [32]byte, procedure string) ([]byte, error) {
	if record.InOwnNamespace(procedure) {
		return nil, nil
	}
	realmKey, pinned := p.opts.RealmTrust[realm]
	if !pinned {
		return nil, ErrNoRealmKey
	}
	return realmKey, nil
}

// ErrNoRealmKey is a realm the pool pins no key for: nothing in it can be
// served or trusted.
var ErrNoRealmKey = errors.New("pool: no realm key pinned for the realm")

// Offer is a procedure the node serves: its realm, which the pool must pin a
// key for, its name, its handler (or Stream, for a streaming procedure:
// exactly one of the two), and its policy: nil serves any caller, a
// ucan.UCANRequired or ucan.RealmMemberRequired a caller whose UCAN it
// authorizes, as stationlink.Offer's does.
type Offer struct {
	Realm     [32]byte
	Procedure string
	Handler   stationlink.Handler
	Stream    *stationlink.StreamOffer
	Policy    ucan.Policy
	// Confidential is how the procedure takes its requests
	// (stationlink.ConfidentialPreferred when zero): with Opts.KEMAdvertise
	// its advertisement names the node's KEM key and sealed requests are
	// answered sealed.
	Confidential stationlink.Confidentiality
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
// after. It returns once one station acknowledges it (macula#12), and fails
// when none does, leaving nothing served: the error joins each link's, in
// which errors.As finds a *stationlink.RefusedError when a station refused it
// and a *stationlink.UnacknowledgedError when one did not answer. Each link
// advertises it naming its own station, and renews and puts it in the DHT as
// stationlink.Serve does; a station that refused it is not asked again until
// its link is dialed again.
func (p *Pool) Serve(ctx context.Context, o Offer) (*Served, error) {
	realmKey, err := p.realmKeyFor(o.Realm, o.Procedure)
	if err != nil {
		return nil, err
	}
	s := &Served{pool: p, onLinks: map[*stationlink.Link]*stationlink.Served{},
		offer: stationlink.Offer{Realm: o.Realm, Procedure: o.Procedure, Handler: o.Handler, Stream: o.Stream, RealmKey: realmKey, Policy: o.Policy,
			Confidential: o.Confidential}}
	if o.Confidential == stationlink.ConfidentialRequired && !p.opts.KEMAdvertise {
		return nil, stationlink.ErrKEMAdvertiseDisabled
	}
	if p.opts.KEMAdvertise && o.Confidential != stationlink.ConfidentialOff {
		// Kept across every link it is served on, so no link reopens the
		// keyless window.
		s.offer.KeyedSince = time.Now()
	}
	links := p.links()
	if len(links) == 0 {
		return nil, ErrNoLink
	}
	// The pool learns of s only after the first round, so a link that comes
	// up meanwhile is served below, never by a replay whose attempt the round
	// would read as its own.
	if err := s.firstServed(ctx, links); err != nil {
		_ = s.Stop()
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = s.Stop()
		return nil, ErrClosed
	}
	p.served[s] = struct{}{}
	p.mu.Unlock()
	for _, link := range p.links() {
		if !slices.Contains(links, link) {
			s.attach(link)
		}
	}
	return s, nil
}

// serveWithin bounds serving on one link: the DHT lookups, then the
// station's REGISTER_ACK, which comes within 30 seconds.
const serveWithin = time.Minute

type linkServed struct {
	link *stationlink.Link
	err  error
}

// firstServed serves the offer on every link at once and returns once one
// station accepts it, or with every link's error when none does: a station's
// refusal is a *stationlink.RefusedError, no answer a
// *stationlink.UnacknowledgedError. The links still unanswered then go on
// within serveWithin, unbound from ctx, and a link that fails other than by
// its station's refusal is tried again as attach does.
func (s *Served) firstServed(ctx context.Context, links []*stationlink.Link) error {
	detached, cancel := context.WithTimeout(context.WithoutCancel(ctx), serveWithin)
	release := context.AfterFunc(ctx, cancel)
	defer release()
	results := make(chan linkServed, len(links))
	var wg sync.WaitGroup
	for _, link := range links {
		wg.Go(func() { results <- linkServed{link, s.serveOn(detached, link)} })
	}
	go func() {
		wg.Wait()
		cancel()
	}()
	var failed []linkServed
	for range links {
		r := <-results
		if r.err != nil {
			failed = append(failed, r)
			continue
		}
		go s.retryFailed(failed, results, len(links)-len(failed)-1)
		return nil
	}
	errs := make([]error, len(failed))
	for i, r := range failed {
		errs[i] = r.err
	}
	return errors.Join(errs...)
}

// retryFailed tries the offer again on each link that failed, or fails among
// the remaining results, other than by its station's refusal.
func (s *Served) retryFailed(failed []linkServed, results <-chan linkServed, remaining int) {
	for range remaining {
		if r := <-results; r.err != nil {
			failed = append(failed, r)
		}
	}
	for _, r := range failed {
		if !refused(r.err) {
			s.attach(r.link)
		}
	}
}

// refused reports whether err is a station's refusal, which serving again on
// the same link would only repeat.
func refused(err error) bool {
	var refusal *stationlink.RefusedError
	return errors.As(err, &refusal)
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
// RespawnDelay while the link lives and the offer is not served there, unless
// its station refuses it.
func (s *Served) attach(link *stationlink.Link) {
	go func() {
		for {
			ctx, cancel := context.WithTimeout(s.pool.ctx, serveWithin)
			err := s.serveOn(ctx, link)
			cancel()
			if err == nil || refused(err) {
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
