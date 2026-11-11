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
// Station discovery beyond the seeds is not here: macula discovers stations
// through mcl-stations/list_stations, which this pool does not call.
//
// A pool may name two lists of stations (macula#201): its seeds are the public
// tier, Opts.FallbackSeeds the fallback tier it keeps for when no public
// station is up. Originating traffic — a publish, a station procedure, a
// content announcement — goes to whichever tier is active, fastest link first;
// standing registrations go to every link of both. See Tier.
package pool

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/seal"
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
	// ErrTooManySeeds is more seeds than MaxSeeds, counting both tiers.
	ErrTooManySeeds = errors.New("pool: more seeds than MaxSeeds")
	// ErrStationInBothTiers is a station named in both the public and the
	// fallback list: one station with two roles has no defined behaviour.
	ErrStationInBothTiers = errors.New("pool: a station is in both the public and the fallback tier")
	// ErrRealmTrustInvalid is a realm key that is not a key of the pool's
	// profile as carried.
	ErrRealmTrustInvalid = errors.New("pool: a realm key is not a well-formed key of the pool's profile")
	// ErrInvalidOpts is an option out of its range, or no identity key.
	ErrInvalidOpts = errors.New("pool: invalid options")
	// ErrNoLink is an operation with no link up to carry it.
	ErrNoLink = errors.New("pool: no station link is up")
	// ErrNotRetryable is a station procedure that is not one a pool walks its
	// links for: a second run of it could give a different result.
	ErrNotRetryable = errors.New("pool: the station procedure is not one a failed link is retried for")
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
	// Tier is the list the link's station was named in, so a binding can report
	// "offline: on the LAN fallback" rather than a bare link going down. A
	// station dialled for a call is TierPublic.
	Tier Tier
	Up   bool
	Err  error
}

// Opts configure a pool. IdentityKey is required; zero values take macula's
// defaults.
type Opts struct {
	// IdentityKey is the node's identity key; its profile is the pool's.
	IdentityKey *identity.NodeKey
	// RealmTrust pins each realm's key, as carried: an advertisement in a
	// realm is trusted only when its authorization verifies against it, and
	// a procedure is served only in a realm it names.
	RealmTrust map[[32]byte][]byte
	// FallbackSeeds are the stations of the fallback tier: the LAN stations a
	// pool keeps for when no public station is up. They are dialed and held
	// like the seeds, and only originating traffic prefers the public tier.
	// Empty, the pool has one tier and behaves as it did before tiers.
	FallbackSeeds     []Seed
	ReplicationFactor int
	// RespawnDelay is the flat wait before a link of the active tier is
	// dialed again; a station whose tier is not the active one takes Redial
	// instead.
	RespawnDelay time.Duration
	// Redial is the schedule a station is dialed again on while its tier is
	// not the active one. Zero fields take macula's defaults.
	Redial Redial
	// Resolve is the schedule a call or stream asks the DHT again on while
	// nothing has been sent: a miss is not final until the deadline
	// (macula-go#76). Zero fields take macula's defaults.
	Resolve Resolve
	// DialTimeout bounds a stream's resolve-and-reach phase: how long an
	// OpenStream keeps asking the DHT and reaching for a provider before it
	// gives up. Zero takes macula's dial timeout, DefaultDialTimeout. It never
	// bounds the stream itself.
	DialTimeout    time.Duration
	MaxSeeds       int
	MaxDirectLinks int
	// Admission bounds the requests the node's served procedures take; zero
	// is macula's defaults, with Cap one share per link the pool may hold.
	Admission     stationlink.AdmissionLimits
	LinkSelection LinkSelection
	// OnLinkEvent, when set, hears every link coming up and going down, on
	// its own goroutine.
	OnLinkEvent func(LinkEvent)
	// KEMAdvertise gives the node a KEM keyring and names its current key in
	// the advertisements of procedures served confidentially (macula 13,
	// E2E design amendment A1), so callers seal to it. Off by default:
	// switch it on only once every station runs macula 12.11 or later and
	// every caller runs 13 (the station floor). Without it the node opens
	// no sealed request.
	KEMAdvertise bool
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
	// waiting holds the publications no link of the active tier took, oldest
	// first, until a link comes up (resend.go), with their size on the wire;
	// waitingSeen is what waits, by publication identity, so a second link that
	// held the same publication does not queue it again.
	waiting      []stationlink.SignedPublication
	waitingSeen  map[[48]byte]struct{}
	waitingBytes int
	// done is the publications the pool has dealt with — one a link took, or
	// one counted unsent — by identity, oldest first in doneOrder while the
	// pool is open, so a copy handed over after its publication already went
	// out is dropped and one already counted is not counted again. An open pool
	// keeps the newest doneRemembered of them; a closing pool keeps every
	// identity it counts, so what it counts is the union of what its links held
	// (resend.go).
	done      map[[48]byte]struct{}
	doneOrder [][48]byte
	// unsent counts the publications this pool accepted and could not carry:
	// expired, no room to wait, or the pool closed with them waiting.
	unsent atomic.Uint64
	// learnt holds the KEM key a provider's signed refusal named, per
	// procedure and provider, until the advertisement it beat would expire
	// (call.go, learnKEMKey).
	learnt map[resolvedKey]learntKey
	closed bool
	ctx    context.Context
	cancel context.CancelFunc

	// sharer is the content this node shares (content.go).
	sharer contentSharer

	// keyring holds the sealed groups this node joined (group.go), nil
	// until the first.
	keyring *group.Keyring
}

// Connect validates the seeds and opts, dials every seed of both tiers, and
// returns once one link is up, or with the last dial's error when ctx ends
// before any is. Links not yet up keep dialing.
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
	var keyring *seal.Keyring
	if opts.KEMAdvertise {
		// One node identity, one keyring, shared by every link.
		if keyring, err = seal.NewKeyring(opts.IdentityKey.Profile(), time.Now); err != nil {
			return nil, err
		}
	}
	runCtx, cancel := context.WithCancel(context.Background())
	p := &Pool{opts: opts, key: opts.IdentityKey, self: self, issuer: issuer,
		shared: stationlink.Config{IdentityKey: opts.IdentityKey, Issuer: issuer, PublicationSeq: &stationlink.PublicationSeq{},
			Keyring: keyring, KEMAdvertise: opts.KEMAdvertise,
			Admission: stationlink.NewAdmission(opts.Admission), Dedup: stationlink.NewEventDedup()},
		subs: map[*Subscription]struct{}{}, served: map[*Served]struct{}{}, remember: map[resolvedKey]candidate{},
		learnt: map[resolvedKey]learntKey{}, waitingSeen: map[[48]byte]struct{}{}, done: map[[48]byte]struct{}{},
		ctx: runCtx, cancel: cancel}
	go issuer.Run(runCtx, opts.OnIssuerError)
	for _, seed := range seeds {
		p.startMember(seed.target(opts.IdentityKey), false, TierPublic)
	}
	for _, seed := range opts.FallbackSeeds {
		p.startMember(seed.target(opts.IdentityKey), false, TierFallback)
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
	if err := checkRealmTrust(opts.RealmTrust, opts.IdentityKey); err != nil {
		return opts, err
	}
	if err := checkLinkLimits(&opts); err != nil {
		return opts, err
	}
	opts.MaxSeeds = orDefault(opts.MaxSeeds, DefaultMaxSeeds)
	opts.MaxDirectLinks = orDefault(opts.MaxDirectLinks, DefaultMaxDirectLinks)
	opts.ReplicationFactor = orDefault(opts.ReplicationFactor, DefaultReplicationFactor)
	if opts.RespawnDelay <= 0 {
		opts.RespawnDelay = DefaultRespawnDelay
	}
	if err := checkSchedules(&opts); err != nil {
		return opts, err
	}
	if opts.Admission == (stationlink.AdmissionLimits{}) {
		opts.Admission = stationlink.DefaultAdmissionLimits()
		opts.Admission.Cap = opts.Admission.Share * (opts.MaxSeeds + opts.MaxDirectLinks)
	}
	if err := opts.Admission.Validate(); err != nil {
		return opts, errors.Join(ErrInvalidOpts, err)
	}
	all := make([]Seed, 0, len(seeds)+len(opts.FallbackSeeds))
	all = append(append(all, seeds...), opts.FallbackSeeds...)
	switch {
	case len(all) == 0:
		return opts, ErrNoSeeds
	case len(all) > opts.MaxSeeds:
		return opts, fmt.Errorf("%w: %d, at most %d", ErrTooManySeeds, len(all), opts.MaxSeeds)
	}
	for _, seed := range all {
		if seed.NodeID == ([32]byte{}) {
			return opts, fmt.Errorf("%w: %s", ErrSeedNotPinned, seed.address())
		}
	}
	if seed, both := stationInBothTiers(seeds, opts.FallbackSeeds); both {
		return opts, fmt.Errorf("%w: %s", ErrStationInBothTiers, seed.address())
	}
	return opts, nil
}

// checkSchedules fills in and refuses the three schedules a pool runs on: the
// redial schedule of a station whose tier is not active, the resolve schedule
// of a call that has sent nothing, and the window a stream's resolve phase gets.
func checkSchedules(opts *Opts) error {
	redial, err := opts.Redial.checked()
	if err != nil {
		return err
	}
	opts.Redial = redial
	resolve, err := opts.Resolve.checked()
	if err != nil {
		return err
	}
	opts.Resolve = resolve
	switch {
	case opts.DialTimeout < 0:
		return fmt.Errorf("%w: a dial timeout of %s", ErrInvalidOpts, opts.DialTimeout)
	case opts.DialTimeout == 0:
		opts.DialTimeout = DefaultDialTimeout
	}
	return nil
}

// checkRealmTrust refuses a realm key that is not well formed under the
// profile the pool links with.
func checkRealmTrust(trust map[[32]byte][]byte, key *identity.NodeKey) error {
	p := key.Profile()
	for realm, realmKey := range trust {
		if !identity.CarriedKeyWellFormed(realmKey, p) {
			return fmt.Errorf("%w: realm %x", ErrRealmTrustInvalid, realm[:4])
		}
	}
	return nil
}

// checkLinkLimits refuses a link limit outside the range the pool supports,
// before the defaults are filled in.
func checkLinkLimits(opts *Opts) error {
	for _, limit := range []*int{&opts.MaxSeeds, &opts.MaxDirectLinks, &opts.ReplicationFactor} {
		if *limit < 0 || *limit > maxLinkLimit {
			return fmt.Errorf("%w: a link limit of %d, outside 1 to %d", ErrInvalidOpts, *limit, maxLinkLimit)
		}
	}
	return nil
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
	// Direct is a station dialled for a call rather than named by the caller.
	Direct bool
	// Tier is the list the station was named in; a direct dial is public.
	Tier Tier
	// Up is whether the link is up now.
	Up bool
}

// Status is every link the pool holds, the public seeds first and the fallback
// seeds after them.
func (p *Pool) Status() []LinkStatus {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	out := make([]LinkStatus, len(members))
	for i, m := range members {
		out[i] = LinkStatus{Station: m.target.ExpectedNodeID, Host: m.target.Host, Port: m.target.Port,
			Direct: m.direct, Tier: m.tier, Up: m.current() != nil}
	}
	return out
}

// isClosed reports whether Close has run.
func (p *Pool) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
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
	keyring := p.keyring
	p.mu.Unlock()
	p.cancel()
	if keyring != nil {
		keyring.Close()
	}
	for _, m := range members {
		m.stop()
	}
	p.countWaiting()
	for sub := range subs {
		sub.end()
	}
	return nil
}

// links is the links up now across both tiers, in the pool's selection order.
// Standing registrations take these; an originating operation takes targets.
func (p *Pool) links() []*stationlink.Link {
	return p.selection(nil)
}

// selection is the links up now on tier, or on every tier when tier is nil, in
// member order, shuffled when the pool selects at random.
func (p *Pool) selection(tier *Tier) []*stationlink.Link {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	var up []*stationlink.Link
	for _, m := range members {
		if tier != nil && m.tier != *tier {
			continue
		}
		if link := m.live(); link != nil {
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
