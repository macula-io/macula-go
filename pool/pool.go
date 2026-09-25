// Package pool is a macula 12 node's set of station links, as macula's client
// pool keeps them: one link to each seed station, every seed pinned by its
// node_id, all links of one node sharing its identity key, statement issuer,
// request admission, publication seq and event dedup. A link that ends is
// dialed again after RespawnDelay and given back the node's subscriptions and
// served procedures.
//
// Calls reach providers directly, as macula 12 calls them: the procedure's
// advertisements are resolved from the DHT and checked against the realm key
// the pool pins for the realm, the serving station an advertisement names is
// dialed (pinned by its node_id, from its own station_endpoint record) and the
// provider called there. Station procedures (_dht.*) go to the pool's links.
//
// Station discovery beyond the seeds is not here: macula's discovery calls
// hecate_stations.list_stations, which the fleet no longer serves
// (macula-io/macula#31), and returns when both SDKs follow mcl-stations.
package pool

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

// The defaults and caps of a pool's bounds, macula's.
const (
	DefaultReplicationFactor = 2
	DefaultRespawnDelay      = time.Second
	DefaultMaxSeeds          = 16
	DefaultMaxDirectLinks    = 8
	maxLinkLimit             = 64
)

var (
	// ErrNoSeeds is a pool given no seed station.
	ErrNoSeeds = errors.New("pool: at least one seed station is needed")
	// ErrSeedNotPinned is a seed without the station's node_id: a pool dials
	// only stations it can check.
	ErrSeedNotPinned = errors.New("pool: every seed needs the station's node_id")
	// ErrTooManySeeds is more seeds than MaxSeeds.
	ErrTooManySeeds = errors.New("pool: more seeds than MaxSeeds")
	// ErrRealmTrustInvalid is a realm key that is not a key of the pool's
	// profile as carried.
	ErrRealmTrustInvalid = errors.New("pool: a realm key is not a well-formed key of the pool's profile")
	// ErrInvalidOpts is an option out of its range, or no identity key.
	ErrInvalidOpts = errors.New("pool: invalid options")
	// ErrNoLink is an operation with no link up to carry it.
	ErrNoLink = errors.New("pool: no station link is up")
	// ErrClosed is an operation on a closed pool.
	ErrClosed = errors.New("pool: closed")
)

// Seed is a station to link to: where it is dialed and the node_id it must
// prove.
type Seed struct {
	Host   string
	Port   uint16
	NodeID [32]byte
}

// LinkSelection is the order Call and Publish try the pool's links in.
type LinkSelection int

const (
	// FirstSuccess tries the links in seed order.
	FirstSuccess LinkSelection = iota
	// Random tries them in a fresh random order each time.
	Random
)

// LinkEvent is a link coming up, or ending or failing to dial with Err.
type LinkEvent struct {
	Station [32]byte
	Direct  bool
	Up      bool
	Err     error
}

// Opts configure a pool. IdentityKey is required; zero values take macula's
// defaults.
type Opts struct {
	// IdentityKey is the node's identity key; its profile is the pool's.
	IdentityKey *identity.NodeKey
	// RealmTrust pins each realm's key, as carried: an advertisement in a
	// realm is trusted only when its authorization verifies against it, and
	// a procedure is served only in a realm it names.
	RealmTrust        map[[32]byte][]byte
	ReplicationFactor int
	RespawnDelay      time.Duration
	MaxSeeds          int
	MaxDirectLinks    int
	// Admission bounds the requests the node's served procedures take; zero
	// is macula's defaults, with Cap one share per link the pool may hold.
	Admission     stationlink.AdmissionLimits
	LinkSelection LinkSelection
	// OnLinkEvent, when set, hears every link coming up and going down, on
	// its own goroutine.
	OnLinkEvent func(LinkEvent)
	// OnIssuerError hears each failure to reissue the node's status
	// statements or rotate its CONNECT key; nil logs it as a warning. Left
	// failing, the links end when their statements lapse.
	OnIssuerError func(error)
}

// Pool is a node's station links.
type Pool struct {
	opts   Opts
	key    *identity.NodeKey
	self   [32]byte
	issuer *identity.StatementIssuer
	shared stationlink.Config

	mu       sync.Mutex
	members  []*member
	subs     map[*Subscription]struct{}
	served   map[*Served]struct{}
	remember map[resolvedKey]candidate
	closed   bool
	ctx      context.Context
	cancel   context.CancelFunc

	// sharer is the content this node shares (content.go).
	sharer contentSharer
}

// Connect validates seeds and opts, dials every seed, and returns once one link
// is up, or with the last dial's error when ctx ends before any is. Links not
// yet up keep dialing.
func Connect(ctx context.Context, seeds []Seed, opts Opts) (*Pool, error) {
	opts, err := checked(seeds, opts)
	if err != nil {
		return nil, err
	}
	self, err := opts.IdentityKey.NodeID()
	if err != nil {
		return nil, errors.Join(ErrInvalidOpts, err)
	}
	issuer, err := identity.NewStatementIssuer(opts.IdentityKey, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return nil, err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	p := &Pool{opts: opts, key: opts.IdentityKey, self: self, issuer: issuer,
		shared: stationlink.Config{IdentityKey: opts.IdentityKey, Issuer: issuer, PublicationSeq: &stationlink.PublicationSeq{},
			Admission: stationlink.NewAdmission(opts.Admission), Dedup: stationlink.NewEventDedup()},
		subs: map[*Subscription]struct{}{}, served: map[*Served]struct{}{}, remember: map[resolvedKey]candidate{},
		ctx: runCtx, cancel: cancel}
	go issuer.Run(runCtx, opts.OnIssuerError)
	for _, seed := range seeds {
		p.startMember(seed.target(opts.IdentityKey), false)
	}
	if err := p.awaitUp(ctx); err != nil {
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (s Seed) target(key *identity.NodeKey) transport.Target {
	return transport.Target{Host: s.Host, Port: s.Port, Profile: key.Profile(), ExpectedNodeID: s.NodeID}
}

// checked refuses, before anything is dialed, what macula's pool refuses, and
// fills in the defaults.
func checked(seeds []Seed, opts Opts) (Opts, error) {
	if opts.IdentityKey == nil || opts.IdentityKey.Purpose() != identity.PurposeIdentity {
		return opts, fmt.Errorf("%w: an identity key is required", ErrInvalidOpts)
	}
	p := opts.IdentityKey.Profile()
	for realm, key := range opts.RealmTrust {
		if !identity.CarriedKeyWellFormed(key, p) {
			return opts, fmt.Errorf("%w: realm %x", ErrRealmTrustInvalid, realm[:4])
		}
	}
	for _, limit := range []*int{&opts.MaxSeeds, &opts.MaxDirectLinks, &opts.ReplicationFactor} {
		if *limit < 0 || *limit > maxLinkLimit {
			return opts, fmt.Errorf("%w: a link limit of %d, outside 1 to %d", ErrInvalidOpts, *limit, maxLinkLimit)
		}
	}
	opts.MaxSeeds = orDefault(opts.MaxSeeds, DefaultMaxSeeds)
	opts.MaxDirectLinks = orDefault(opts.MaxDirectLinks, DefaultMaxDirectLinks)
	opts.ReplicationFactor = orDefault(opts.ReplicationFactor, DefaultReplicationFactor)
	if opts.RespawnDelay <= 0 {
		opts.RespawnDelay = DefaultRespawnDelay
	}
	if opts.Admission == (stationlink.AdmissionLimits{}) {
		opts.Admission = stationlink.DefaultAdmissionLimits()
		opts.Admission.Cap = opts.Admission.Share * (opts.MaxSeeds + opts.MaxDirectLinks)
	}
	if err := opts.Admission.Validate(); err != nil {
		return opts, errors.Join(ErrInvalidOpts, err)
	}
	switch {
	case len(seeds) == 0:
		return opts, ErrNoSeeds
	case len(seeds) > opts.MaxSeeds:
		return opts, fmt.Errorf("%w: %d, at most %d", ErrTooManySeeds, len(seeds), opts.MaxSeeds)
	}
	for _, seed := range seeds {
		if seed.NodeID == ([32]byte{}) {
			return opts, fmt.Errorf("%w: %s", ErrSeedNotPinned, net.JoinHostPort(seed.Host, strconv.Itoa(int(seed.Port))))
		}
	}
	return opts, nil
}

func orDefault(v, fallback int) int {
	if v == 0 {
		return fallback
	}
	return v
}

// NodeID is the node_id the pool links as.
func (p *Pool) NodeID() [32]byte { return p.self }

// LinkStatus is one of the pool's links.
type LinkStatus struct {
	Station [32]byte
	Host    string
	Port    uint16
	Direct  bool
	Up      bool
}

// Status is every link the pool holds, seeds first.
func (p *Pool) Status() []LinkStatus {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	out := make([]LinkStatus, len(members))
	for i, m := range members {
		out[i] = LinkStatus{Station: m.target.ExpectedNodeID, Host: m.target.Host, Port: m.target.Port,
			Direct: m.direct, Up: m.current() != nil}
	}
	return out
}

// Close ends every link with GOODBYE and every subscription, and withdraws
// nothing: an advertisement lapses with its link.
func (p *Pool) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	members := p.members
	subs := p.subs
	p.subs = map[*Subscription]struct{}{}
	p.mu.Unlock()
	p.cancel()
	for _, m := range members {
		m.stop()
	}
	for sub := range subs {
		sub.end()
	}
	return nil
}

// links is the links up now, in the pool's selection order.
func (p *Pool) links() []*stationlink.Link {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	var up []*stationlink.Link
	for _, m := range members {
		if link := m.current(); link != nil {
			up = append(up, link)
		}
	}
	if p.opts.LinkSelection == Random {
		rand.Shuffle(len(up), func(i, j int) { up[i], up[j] = up[j], up[i] })
	}
	return up
}

// awaitUp waits until a link is up, or ctx ends.
func (p *Pool) awaitUp(ctx context.Context) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if len(p.links()) > 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", ErrNoLink, errors.Join(ctx.Err(), p.lastErr()))
		case <-ticker.C:
		}
	}
}

func (p *Pool) lastErr() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, m := range p.members {
		if err := m.lastErr(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (p *Pool) event(e LinkEvent) {
	if p.opts.OnLinkEvent != nil {
		go p.opts.OnLinkEvent(e)
	}
}
