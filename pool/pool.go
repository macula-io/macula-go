// Package pool ports macula_client.erl's connection-pool design —
// macula-station itself depends on this in Erlang — to macula-go: hold
// live links to N stations, respawn a dead one with backoff, and replay
// every tracked subscription onto the fresh link so a caller's
// subscription survives a link dying underneath it. connection.Session
// itself deliberately does none of this — see its own doc: "reconnecting
// and replaying subscriptions ... onto a fresh session is the caller's
// responsibility."
//
// Design note on why this isn't "one Session per seed, subscribe
// directly": confirmed by reading connection/frame_stream.go,
// subscriber.go and serve.go that a Session's control stream supports
// exactly ONE concurrent reader (Call, RunSubscriber and ServeOneCall
// each document this) and has no write-side lock either. A pool that
// needs one link to carry N tracked subscriptions plus outbound Call
// fan-out needs to demux those itself — see actor.go's own doc for the
// reader/writer/actor split this package uses to do that (reviewed
// adversarially before implementation; that review is why writes are
// queued through a separate goroutine rather than sent inline from the
// dispatch loop, and why an inbound CALL — out of scope for v1, see
// below — would need to run on its own spawned goroutine rather than
// inline).
//
// v1 scope: Connect/Close/Status/Publish/Subscribe/Unsubscribe/Call/
// CallStation (direct-dial, macula_client.erl's call_station/6). NOT in
// v1, deliberately, not silently: serving RPCs through the pool
// (Advertise/ServeForever-equivalent — no CallLookup/procs/UCAN-policy
// plumbing here yet) and per-publisher delivery ORDERING
// (macula_client.erl defaults to `ordered` with a reorder buffer; this
// package does dedup only, and does NOT preserve even arrival order —
// subscribe.go's deliver spawns one goroutine per delivery, so two
// events for the same subscriber can be handled in either order,
// weaker than even macula_client.erl's own weakest `as_arrives` mode).
// Both are real macula_client.erl capabilities left as a follow-up, not
// gaps to discover later.
package pool

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// ErrNoHealthyStation matches macula_client.erl's own
// {error, {transient, no_healthy_station}} — zero links currently
// connected for the operation attempted.
var ErrNoHealthyStation = errors.New("pool: no healthy station")

const (
	// DefaultReplicationFactor matches macula_client.erl's own default.
	DefaultReplicationFactor = 1
	// DefaultRespawnDelay matches macula_client.erl's own
	// ?LINK_RESPAWN_DELAY_MS -- flat, not exponential; Erlang has no
	// backoff curve here and there's no existing Go precedent in this
	// codebase to match instead, so this mirrors the reference exactly.
	DefaultRespawnDelay = 1 * time.Second
	// DefaultDedupWindow/DefaultDedupSweep match macula_client.erl's own
	// dedup_window_ms/dedup_sweep_ms defaults.
	DefaultDedupWindow = 60 * time.Second
	DefaultDedupSweep  = 30 * time.Second
	// DefaultConnectTimeout bounds one link's CONNECT/HELLO handshake --
	// matches connection.HandshakeTimeout.
	DefaultConnectTimeout = 30 * time.Second
	// DefaultStationDiscoveryRefreshInterval/DefaultStationDiscoveryMaxLinks
	// match macula_client.erl's own station_discovery defaults
	// (refresh_ms/max_links) exactly, only applied when
	// StationDiscovery.Enabled is true.
	DefaultStationDiscoveryRefreshInterval = 30 * time.Minute
	DefaultStationDiscoveryMaxLinks        = 5
)

// Seed is one seed station to dial at Connect -- re-exported so callers
// don't need to import package connection just to build one.
type Seed = connection.Seed

// EventHandler processes one delivered EVENT. Runs on its own goroutine
// per delivery (see fanoutEvents' own doc) -- a slow or panicking
// handler affects only its own delivery, never the pool's dispatch path.
type EventHandler func(realm []byte, topic string, payload cbor.Value)

// SubID identifies one Subscribe call, for a later Unsubscribe.
type SubID uint64

// LinkSelection picks how Call/Publish order the pool's currently-
// connected links before applying their own existing first-match/
// replication-factor logic -- it changes ORDER only, never how many
// links get used. CallStation is deliberately NOT in scope: it dials
// one specific target, not a selection among several, so there is no
// order for this option to affect. Matches macula_client.erl's own
// link_selection option exactly (first_success/random), so a caller
// porting config from the Erlang reference (or another SDK) doesn't
// have to re-learn the shape.
type LinkSelection int

const (
	// LinkSelectionAuto (the zero value) derives the actual policy from
	// StationDiscovery.Enabled: LinkSelectionFirstSuccess if discovery is
	// off (today's exact behavior, unchanged), LinkSelectionRandom if
	// it's on. Set LinkSelection explicitly to override that pairing
	// either way.
	LinkSelectionAuto LinkSelection = iota
	// LinkSelectionFirstSuccess tries links in whatever order
	// connectedActors() currently returns them, first non-error wins --
	// this package's original, pre-existing behavior. Note that order
	// was never actually deliberate: p.links is a map, and Go
	// randomizes map iteration, so this policy already had incidental,
	// undocumented variation baked in -- LinkSelectionFirstSuccess makes
	// that historical accident irrelevant by not caring about order at
	// all beyond "whatever connectedActors() hands back."
	LinkSelectionFirstSuccess
	// LinkSelectionRandom uniformly shuffles the connected-links list
	// before the same first-match (Call) or take-first-N (Publish)
	// logic runs. This is a real, deliberate, tested rotation -- not an
	// accident of a map -- and composes safely with a small
	// ReplicationFactor (shuffling a 1-element slice is a no-op).
	LinkSelectionRandom
)

// StationDiscoveryOpts configures opt-in discovery of additional
// stations via hecate_stations.list_stations, layered on top of the
// caller-supplied bootstrap Seeds. Absent (the zero value, Enabled ==
// false) is a complete no-op -- zero config means zero behavior
// change, matching macula_client.erl's own station_discovery option.
//
// Bootstrap Seeds keep their exact current meaning: dialed first,
// permanent fallback if discovery never succeeds, never replaced.
// Discovery only ADDS links (via the pool's own addLink, which is
// already a no-op for an already-known host:port) -- a station
// missing from a later refresh does NOT tear down an existing link;
// removal stays tied to the existing crash/DOWN cleanup only, never
// to absence from a discovery response (replication lag in the
// station directory isn't evidence a station is gone).
type StationDiscoveryOpts struct {
	Enabled bool
	// RefreshInterval between discovery attempts once at least one
	// bootstrap link is up. 0 -> DefaultStationDiscoveryRefreshInterval.
	RefreshInterval time.Duration
	// MaxLinks bounds discovery's OWN adds only, not this Pool's total
	// link count: discovery adds a link only while linkCount() (every
	// link this Pool holds, from any source -- Seeds, CallStation
	// direct-dial targets, and previously discovered ones, healthy or
	// not) is still below MaxLinks. Connect dials every bootstrap Seed
	// regardless of MaxLinks (more Seeds than MaxLinks means discovery
	// simply adds nothing, ever), and CallStation adds its own link
	// regardless too -- but once added, a CallStation link DOES count
	// toward the total linkCount() compares against, consuming
	// discovery's budget even though CallStation itself never checks
	// MaxLinks. A link discovery added that never connects (e.g. a
	// station whose only known address isn't dialable under this
	// Pool's Trust) still occupies a slot against this cap even while
	// permanently unhealthy -- there is no separate "healthy slots"
	// budget. 0 -> DefaultStationDiscoveryMaxLinks.
	MaxLinks int
}

// Opts configures a Pool. Zero-value Opts is invalid -- Identity has no
// safe default the way Erlang's resolve_identity generates a
// puzzle-hardened one lazily, because Go's identity.GenerateWithPuzzle
// is not free to call unconditionally at every Connect (see that
// package's own doc); callers wanting the same lazy-generate-if-absent
// behavior should call it themselves before building Opts.
type Opts struct {
	Identity          identity.KeyPair
	Trust             transport.Trust
	ReplicationFactor int           // 0 -> DefaultReplicationFactor
	ConnectTimeout    time.Duration // 0 -> DefaultConnectTimeout
	RespawnDelay      time.Duration // 0 -> DefaultRespawnDelay
	DedupWindow       time.Duration // 0 -> DefaultDedupWindow
	DedupSweep        time.Duration // 0 -> DefaultDedupSweep
	// LivenessInterval/LivenessMaxMisses configure the application-level
	// probe every link runs on top of the transport's own keepalive --
	// see actor.go's tickLiveness for why the transport layer alone
	// isn't enough. 0 -> DefaultLivenessInterval/DefaultLivenessMaxMisses.
	LivenessInterval  time.Duration
	LivenessMaxMisses int

	// OnLinkEvent, if set, is called on every link lifecycle transition —
	// a dial failure, a successful (re)connect, or a live link dying —
	// with linkKey identifying which configured target (host:port) it
	// concerns, up true only for a successful (re)connect, and err set
	// for everything else. Optional; nil is a no-op. Without this, a
	// link that fails to dial over and over (wrong port, an identity the
	// station's puzzle check rejects, TLS refusal) is completely silent
	// from outside the pool — Status only ever reports it as "not
	// healthy," never why. Called on its own goroutine so a slow or
	// panicking callback can never stall replay for every other link —
	// same reasoning as event delivery's own per-handler goroutine.
	OnLinkEvent func(linkKey string, up bool, err error)

	// LinkSelection picks Call/Publish's link ordering policy -- see
	// LinkSelection's own doc. Zero value (LinkSelectionAuto) derives it
	// from StationDiscovery.Enabled.
	LinkSelection LinkSelection
	// StationDiscovery opts into resolving additional stations via
	// hecate_stations.list_stations -- see StationDiscoveryOpts' own
	// doc. Zero value (Enabled == false) is a complete no-op.
	StationDiscovery StationDiscoveryOpts

	dial dialFunc // test-only seam; nil -> dialSession
}

func (o Opts) withDefaults() Opts {
	if o.ReplicationFactor <= 0 {
		o.ReplicationFactor = DefaultReplicationFactor
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = DefaultConnectTimeout
	}
	if o.RespawnDelay <= 0 {
		o.RespawnDelay = DefaultRespawnDelay
	}
	if o.DedupWindow <= 0 {
		o.DedupWindow = DefaultDedupWindow
	}
	if o.DedupSweep <= 0 {
		o.DedupSweep = DefaultDedupSweep
	}
	if o.LivenessInterval <= 0 {
		o.LivenessInterval = DefaultLivenessInterval
	}
	if o.LivenessMaxMisses <= 0 {
		o.LivenessMaxMisses = DefaultLivenessMaxMisses
	}
	if o.LinkSelection == LinkSelectionAuto {
		if o.StationDiscovery.Enabled {
			o.LinkSelection = LinkSelectionRandom
		} else {
			o.LinkSelection = LinkSelectionFirstSuccess
		}
	}
	if o.StationDiscovery.Enabled {
		if o.StationDiscovery.RefreshInterval <= 0 {
			o.StationDiscovery.RefreshInterval = DefaultStationDiscoveryRefreshInterval
		}
		if o.StationDiscovery.MaxLinks <= 0 {
			o.StationDiscovery.MaxLinks = DefaultStationDiscoveryMaxLinks
		}
	}
	if o.dial == nil {
		o.dial = dialSession
	}
	return o
}

type topicKey struct{ realm, topic string }

type subSpec struct {
	realm   []byte
	topic   string
	handler EventHandler
}

// Pool is a live handle to N links, reconnecting and replaying
// subscriptions as needed. Construct with Connect.
type Pool struct {
	opts Opts

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	linksMu sync.RWMutex
	links   map[string]*link

	subsMu     sync.Mutex
	subs       map[SubID]*subSpec
	topicIndex map[topicKey]map[SubID]struct{}
	nextSubID  atomic.Uint64

	dedup *dedupTable

	publishSeq atomic.Uint64

	events    chan inboundEvent
	linkEvent chan linkEvent
}

// Connect spawns one link per seed, dialing all of them concurrently --
// not one-then-fallback -- and returns immediately; handshakes complete
// asynchronously, exactly like macula_client.erl's own connect/2. Publish
// and Call return ErrNoHealthyStation until at least one link is up;
// Subscribe succeeds immediately and is replayed onto every link as it
// (re)connects.
func Connect(ctx context.Context, seeds []Seed, opts Opts) (*Pool, error) {
	if len(seeds) == 0 {
		return nil, fmt.Errorf("pool: no seeds given")
	}
	if opts.Trust == nil {
		return nil, fmt.Errorf("pool: opts.Trust is required")
	}
	if !opts.Identity.Valid() {
		return nil, fmt.Errorf("pool: opts.Identity is required (zero-value KeyPair)")
	}
	opts = opts.withDefaults()

	poolCtx, cancel := context.WithCancel(ctx)
	p := &Pool{
		opts:       opts,
		ctx:        poolCtx,
		cancel:     cancel,
		links:      make(map[string]*link),
		subs:       make(map[SubID]*subSpec),
		topicIndex: make(map[topicKey]map[SubID]struct{}),
		dedup:      newDedupTable(),
		events:     make(chan inboundEvent, eventQueueCap),
		linkEvent:  make(chan linkEvent, 16),
	}
	// Seeded from wall-clock microseconds, matching macula_client.erl's
	// own publish_seq init -- a pool restart must not re-issue seqs that
	// collide with the pre-restart tail still inside a station's own
	// dedup window.
	p.publishSeq.Store(uint64(time.Now().UnixMicro()))

	p.wg.Add(3)
	go func() { defer p.wg.Done(); p.watchLinks() }()
	go func() { defer p.wg.Done(); p.fanoutEvents() }()
	go func() { defer p.wg.Done(); p.sweepDedup() }()

	for _, seed := range seeds {
		p.addLink(seed.Host, seed.Port, opts.Trust)
	}

	// wg.Add happens here, synchronously, before Connect returns and
	// before any concurrent Close() could observe the WaitGroup at
	// zero -- same safe pattern the 3 fixed goroutines above already
	// use. Bootstrap Seeds keep their exact current meaning either way
	// (dialed above, permanent fallback) -- discovery is additive on
	// top, never a replacement; see StationDiscoveryOpts' own doc.
	if opts.StationDiscovery.Enabled {
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.discoverStations() }()
	}

	return p, nil
}

// addLink registers and starts supervising a link for host:port under
// trust, if one doesn't already exist for that exact key. Safe from any
// goroutine.
func (p *Pool) addLink(host string, port uint16, trust transport.Trust) *link {
	key := linkKey(host, port)

	p.linksMu.Lock()
	if existing, ok := p.links[key]; ok {
		p.linksMu.Unlock()
		return existing
	}
	l := newLink(host, port, trust, p.opts.Identity, p.opts.dial, p.opts.RespawnDelay,
		p.opts.LivenessInterval, p.opts.LivenessMaxMisses, p.events, p.linkEvent)
	p.links[key] = l
	p.linksMu.Unlock()

	p.wg.Add(1)
	go func() { defer p.wg.Done(); l.supervise(p.ctx) }()
	return l
}

// Close cancels every link and waits for each link's supervise loop
// (and its current actor's run(), which that loop calls synchronously)
// to return. It does NOT explicitly join an actor's own reader/writer
// goroutines -- they're stopped via the same cancelled context, and
// every send they could still attempt is itself guarded against that
// context, so they can't block past it, but a brief window where one
// is still returning after run() itself has already returned is
// possible. Harmless: nothing is shared between one generation's
// goroutines and the next, only the (already dead) session they were
// reading/writing.
func (p *Pool) Close() error {
	p.cancel()
	p.wg.Wait()
	return nil
}

// Status is an aggregate health snapshot -- see macula_client.erl's own
// status/1.
type Status struct {
	ConfiguredLinks int
	HealthyLinks    int
	Subscriptions   int
}

func (p *Pool) Status() Status {
	p.linksMu.RLock()
	total, healthy := len(p.links), 0
	for _, l := range p.links {
		if l.CurrentActor() != nil {
			healthy++
		}
	}
	p.linksMu.RUnlock()

	p.subsMu.Lock()
	subCount := len(p.subs)
	p.subsMu.Unlock()

	return Status{ConfiguredLinks: total, HealthyLinks: healthy, Subscriptions: subCount}
}

// connectedActors snapshots the currently-live actors across every
// configured link.
func (p *Pool) connectedActors() []*actor {
	p.linksMu.RLock()
	defer p.linksMu.RUnlock()
	actors := make([]*actor, 0, len(p.links))
	for _, l := range p.links {
		if a := l.CurrentActor(); a != nil {
			actors = append(actors, a)
		}
	}
	return actors
}

// selectLinks returns connectedActors() ordered per p.opts.LinkSelection --
// the single shared choke point Call and Publish both route through, so
// the two operations can never drift onto different selection policies
// by accident. LinkSelectionFirstSuccess passes the list through
// unchanged (today's original behavior: whatever order connectedActors()
// happens to return, which was always map-iteration-random and never
// actually deliberate -- see LinkSelectionFirstSuccess's own doc).
// LinkSelectionRandom uniformly shuffles a COPY of the list (never the
// slice connectedActors() just built in place, and never anything
// touching p.links itself) via math/rand/v2, which needs no seeding and
// is safe for concurrent use from multiple goroutines calling Call/
// Publish at once -- unlike math/rand's global source pre-v2, which
// needed its own lock and a deliberate seed to avoid every process
// producing the identical shuffle sequence.
func (p *Pool) selectLinks() []*actor {
	actors := p.connectedActors()
	if p.opts.LinkSelection != LinkSelectionRandom || len(actors) <= 1 {
		return actors
	}
	shuffled := make([]*actor, len(actors))
	copy(shuffled, actors)
	mathrand.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	return shuffled
}
