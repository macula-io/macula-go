package group

import (
	"cmp"
	"context"
	"errors"
	"math/rand/v2"
	"slices"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/stationlink"
)

// Reason is why a group's key could not be had or an event could not be
// opened: the closed set every SDK names (DESIGN_E2E_SEALED_PUBSUB.md §7).
type Reason string

const (
	ReasonNotAMember        Reason = "not_a_member"
	ReasonMembershipUnknown Reason = "membership_unknown"
	ReasonUnknownEpoch      Reason = "unknown_epoch"
	ReasonEpochExpired      Reason = "epoch_expired"
	ReasonNoDistributor     Reason = "no_distributor"
	ReasonNoGroup           Reason = "no_group"
	ReasonTagInvalid        Reason = "tag_invalid"
)

// Error is a refusal or failure by its Reason, with the pull's own error
// when there was one.
type Error struct {
	Reason Reason
	Err    error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return "group: " + string(e.Reason) + ": " + e.Err.Error()
	}
	return "group: " + string(e.Reason)
}

func (e *Error) Unwrap() error { return e.Err }

// Is matches another *Error of the same reason, so errors.Is(err,
// &Error{ReasonNotAMember}) reads as it says.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Reason == e.Reason
}

func reasonError(r Reason) error { return &Error{Reason: r} }

// ReasonOf is err's Reason, and whether it has one.
func ReasonOf(err error) (Reason, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e.Reason, true
	}
	return "", false
}

// ErrNotJoined is a publish or an open under a group this keyring does not
// hold.
var ErrNotJoined = errors.New("group: the group is not joined")

// ErrNotAdvertised is a pull that found no trusted distributor advertising
// the procedure; the Puller wraps its own error in it.
var ErrNotAdvertised = errors.New("group: no trusted distributor advertises the group's procedure")

// refusals are the distributor's refusals as it details them (a provider
// error with code handler_error), each by the reason it is held as. A prefix
// another org owns is the distributor's to refuse, and to a member it is no
// distributor of its group.
var refusals = map[string]Reason{
	"not_a_member":       ReasonNotAMember,
	"membership_unknown": ReasonMembershipUnknown,
	"unknown_epoch":      ReasonUnknownEpoch,
	"epoch_expired":      ReasonEpochExpired,
	"unknown_group":      ReasonNoDistributor,
}

// Pull is one call to a group's distributor: always sealed to the KEM key its
// advertisement names (a keyless advertisement is never a distributor), with
// the org's grant as the call's UCAN, and at the pinned distributor when
// Provider is not zero.
type Pull struct {
	Realm     [32]byte
	Procedure string
	Payload   cbor.Value
	Token     []byte
	Provider  [32]byte
}

// Puller makes a pull and returns its result and the node that answered.
// Wrap ErrNotAdvertised when no trusted distributor advertises the
// procedure; a provider's refusal is a *stationlink.ProviderError.
type Puller func(ctx context.Context, p Pull) (cbor.Value, [32]byte, error)

// Options are a keyring's pull, and its clock, jitter and timer for tests;
// each defaults to the real one.
type Options struct {
	Pull        Puller
	PullTimeout time.Duration
	Now         func() int64
	Uniform     func() float64
	AfterFunc   func(d time.Duration, f func()) func() bool
}

// JoinOptions are a join's grant and pin: the org's UCAN, presented on every
// pull, and the distributor's node id when it must be that node (required
// for a `~<node_id>` group, available for an org's).
type JoinOptions struct {
	UCAN        []byte
	Distributor *[32]byte
}

const (
	defaultPullTimeout     = 15 * time.Second
	firstBackoffMs         = 1_000
	unknownIDsPerPublisher = 3
)

type groupKey struct {
	realm  [32]byte
	prefix string
}

type pinKind int

const (
	pinNone pinKind = iota
	pinUser
	pinAuto
)

type budget struct {
	since int64
	count int
}

// held is a joined group: what its pulls set, and its re-pull.
type held struct {
	org      string
	ucan     []byte
	pin      [32]byte
	pinKind  pinKind
	policy   Policy
	epochs   []Epoch
	rotation int64
	unknown  map[[IDSize]byte]int64
	budget   map[[32]byte]budget
	backoff  int64
	stop     func() bool
	wake     uint64
}

// Keyring holds the sealed groups a node joined: their epochs, policy and
// re-pulls (DESIGN_E2E_SEALED_PUBSUB.md §4, §6, §7). Publishing under a
// current epoch, opening under a held one and reading a policy never wait on
// a pull; pulls are made one at a time. Every held group is pulled again at
// a uniformly random instant in its newest epoch's ahead window, event or no
// event, and a failed pull is retried with backoff, doubling from 1 second
// up to a third of an epoch, until one succeeds. The policy is monotonic: once
// Preferred or Required has been seen for a prefix, Off is ignored. Epoch
// keys are held in memory only, and erased when no event under them can be
// accepted any more.
type Keyring struct {
	opts   Options
	pullMu sync.Mutex

	mu     sync.Mutex
	groups map[groupKey]*held
	closed bool
}

// NewKeyring is a keyring pulling with opts.Pull.
func NewKeyring(opts Options) *Keyring {
	if opts.PullTimeout <= 0 {
		opts.PullTimeout = defaultPullTimeout
	}
	if opts.Now == nil {
		opts.Now = func() int64 { return time.Now().UnixMilli() }
	}
	if opts.Uniform == nil {
		opts.Uniform = rand.Float64
	}
	if opts.AfterFunc == nil {
		opts.AfterFunc = func(d time.Duration, f func()) func() bool { return time.AfterFunc(d, f).Stop }
	}
	return &Keyring{opts: opts, groups: map[groupKey]*held{}}
}

// Close stops every re-pull and erases every group's keys.
func (k *Keyring) Close() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.closed = true
	for key, g := range k.groups {
		stopTimer(g)
		delete(k.groups, key)
	}
}

// Join joins the group prefix in realm: pulls its current epoch and holds
// it. A group already held is not pulled again. It answers the group's
// policy, or the pull's refusal.
func (k *Keyring) Join(ctx context.Context, realm [32]byte, prefix string, opts JoinOptions) (Policy, error) {
	org, err := OrgOf(prefix)
	if err != nil {
		return "", err
	}
	key := groupKey{realm, prefix}
	k.pullMu.Lock()
	defer k.pullMu.Unlock()
	k.mu.Lock()
	if g, ok := k.groups[key]; ok {
		policy := g.policy
		k.mu.Unlock()
		return policy, nil
	}
	k.mu.Unlock()
	g := &held{org: org, ucan: opts.UCAN, unknown: map[[IDSize]byte]int64{}, budget: map[[32]byte]budget{},
		backoff: firstBackoffMs}
	if opts.Distributor != nil {
		g.pin, g.pinKind = *opts.Distributor, pinUser
	}
	reply, err := k.pull(ctx, key, g, CurrentRequest(prefix))
	if err != nil {
		return "", err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.closed {
		return "", ErrNotJoined
	}
	g.merge(reply)
	k.groups[key] = g
	k.scheduleLocked(key, g)
	return g.policy, nil
}

// Leave stops holding the group and erases its keys.
func (k *Keyring) Leave(realm [32]byte, prefix string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	key := groupKey{realm, prefix}
	if g, ok := k.groups[key]; ok {
		stopTimer(g)
		delete(k.groups, key)
	}
}

// Policy is the joined group covering topic (its longest joined prefix) and
// that group's policy, or false when none does.
func (k *Keyring) Policy(realm [32]byte, topic string) (string, Policy, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	best, policy, found := "", Policy(""), false
	for key, g := range k.groups {
		if key.realm == realm && Under(topic, key.prefix) && len(key.prefix) >= len(best) {
			best, policy, found = key.prefix, g.policy, true
		}
	}
	return best, policy, found
}

// PublishEpoch is the epoch a publisher seals under now: the newest held
// epoch that has started and not stopped publishing. With none, the group is
// pulled at once, and the publish fails closed with that pull's error.
func (k *Keyring) PublishEpoch(ctx context.Context, realm [32]byte, prefix string) (Epoch, error) {
	key := groupKey{realm, prefix}
	if e, err, done := k.currentEpoch(key); done {
		return e, err
	}
	k.pullMu.Lock()
	defer k.pullMu.Unlock()
	if e, err, done := k.currentEpoch(key); done {
		return e, err
	}
	g, ok := k.group(key)
	if !ok {
		return Epoch{}, ErrNotJoined
	}
	reply, err := k.pull(ctx, key, g, CurrentRequest(prefix))
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil {
		k.backOffLocked(key, g)
		return Epoch{}, err
	}
	g.merge(reply)
	k.storeLocked(key, g)
	k.scheduleLocked(key, g)
	if e, ok := forPublish(g.epochs, k.opts.Now()); ok {
		return e, nil
	}
	return Epoch{}, reasonError(ReasonNoDistributor)
}

func (k *Keyring) currentEpoch(key groupKey) (Epoch, error, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	g, ok := k.groups[key]
	if !ok {
		return Epoch{}, ErrNotJoined, true
	}
	if e, ok := forPublish(g.epochs, k.opts.Now()); ok {
		return e, nil, true
	}
	return Epoch{}, nil, false
}

// OpenEpoch is the epoch id an event from publisher was sealed under, if it
// may be opened now: a held one while it is acceptable; otherwise it is
// pulled by id, at most three unknown ids per publisher per rotation, and an
// unknown_epoch answer is remembered until the id could no longer be
// accepted anyway.
func (k *Keyring) OpenEpoch(ctx context.Context, realm [32]byte, prefix string, id [IDSize]byte, publisher [32]byte) (Epoch, error) {
	key := groupKey{realm, prefix}
	if e, err, done := k.heldEpoch(key, id); done {
		return e, err
	}
	k.pullMu.Lock()
	defer k.pullMu.Unlock()
	if e, err, done := k.heldEpoch(key, id); done {
		return e, err
	}
	k.mu.Lock()
	g, ok := k.groups[key]
	if !ok {
		k.mu.Unlock()
		return Epoch{}, ErrNotJoined
	}
	now := k.opts.Now()
	if g.unknown[id] > now || !g.spend(publisher, now) {
		k.mu.Unlock()
		return Epoch{}, reasonError(ReasonUnknownEpoch)
	}
	k.mu.Unlock()
	reply, err := k.pull(ctx, key, g, ByIDRequest(prefix, id))
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil {
		if r, _ := ReasonOf(err); r == ReasonUnknownEpoch {
			g.unknown[id] = now + eventLifeMs
		}
		return Epoch{}, err
	}
	g.merge(reply)
	k.storeLocked(key, g)
	for _, e := range g.epochs {
		if e.ID == id {
			if !e.acceptable(k.opts.Now()) {
				return Epoch{}, reasonError(ReasonEpochExpired)
			}
			return e, nil
		}
	}
	return Epoch{}, reasonError(ReasonNoDistributor)
}

func (k *Keyring) heldEpoch(key groupKey, id [IDSize]byte) (Epoch, error, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	g, ok := k.groups[key]
	if !ok {
		return Epoch{}, ErrNotJoined, true
	}
	for _, e := range g.epochs {
		if e.ID == id {
			if !e.acceptable(k.opts.Now()) {
				return Epoch{}, reasonError(ReasonEpochExpired), true
			}
			return e, nil, true
		}
	}
	return Epoch{}, nil, false
}

func (k *Keyring) group(key groupKey) (*held, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	g, ok := k.groups[key]
	return g, ok
}

// pull makes one pull for g under pullMu, outside mu. On a reply it answers
// the parsed reply, and keeps the answering node as the group's distributor
// when none is pinned; on a failure, the reason it is held as.
func (k *Keyring) pull(ctx context.Context, key groupKey, g *held, payload cbor.Value) (Reply, error) {
	k.mu.Lock()
	p := Pull{Realm: key.realm, Procedure: Procedure(g.org), Payload: payload, Token: g.ucan}
	if g.pinKind != pinNone {
		p.Provider = g.pin
	}
	k.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, k.opts.PullTimeout)
	defer cancel()
	result, provider, err := k.opts.Pull(ctx, p)
	k.mu.Lock()
	defer k.mu.Unlock()
	if err != nil {
		if errors.Is(err, ErrNotAdvertised) && g.pinKind == pinAuto {
			g.pinKind = pinNone
		}
		return Reply{}, &Error{Reason: refusalOf(err), Err: err}
	}
	reply, err := ParseReply(key.prefix, result)
	if err != nil {
		return Reply{}, &Error{Reason: ReasonNoDistributor, Err: err}
	}
	if g.pinKind == pinNone {
		g.pin, g.pinKind = provider, pinAuto
	}
	return reply, nil
}

// refusalOf is a failed pull's reason: the distributor's named refusal, or
// no_distributor for one that cannot be found, reached or understood.
func refusalOf(err error) Reason {
	var pe *stationlink.ProviderError
	if errors.As(err, &pe) && pe.Code == "handler_error" && pe.Detail != nil {
		if r, ok := refusals[*pe.Detail]; ok {
			return r
		}
	}
	return ReasonNoDistributor
}

// merge takes a reply into g: its policy, monotonically, its rotation, and
// its epochs the group does not hold yet.
func (g *held) merge(r Reply) {
	if r.Policy != PolicyOff || (g.policy != PolicyPreferred && g.policy != PolicyRequired) {
		g.policy = r.Policy
	}
	g.rotation = r.Epochs[0].rotation()
	for _, e := range r.Epochs {
		if !slices.ContainsFunc(g.epochs, func(h Epoch) bool { return h.ID == e.ID }) {
			g.epochs = append(g.epochs, e)
		}
	}
	slices.SortStableFunc(g.epochs, func(a, b Epoch) int { return cmp.Compare(a.IssuedAt, b.IssuedAt) })
}

// spend charges one unknown-id pull to publisher, at most three per rotation.
func (g *held) spend(publisher [32]byte, now int64) bool {
	b, ok := g.budget[publisher]
	switch {
	case !ok || now-b.since >= g.rotation:
		g.budget[publisher] = budget{since: now, count: 1}
	case b.count >= unknownIDsPerPublisher:
		return false
	default:
		g.budget[publisher] = budget{since: b.since, count: b.count + 1}
	}
	return true
}

// storeLocked erases the group's epochs no longer of use.
func (k *Keyring) storeLocked(key groupKey, g *held) {
	g.epochs = live(g.epochs, k.opts.Now())
	if _, joined := k.groups[key]; joined {
		k.groups[key] = g
	}
}

// scheduleLocked sets the group's one re-pull at a random instant in its
// newest epoch's ahead window, or at once if that has passed, and resets
// its backoff.
func (k *Keyring) scheduleLocked(key groupKey, g *held) {
	g.backoff = firstBackoffMs
	k.storeLocked(key, g)
	if len(g.epochs) == 0 {
		k.wakeInLocked(key, g, 0)
		return
	}
	at := g.epochs[len(g.epochs)-1].repullAt(k.opts.Uniform())
	k.wakeInLocked(key, g, max(0, at-k.opts.Now()))
}

// backOffLocked retries a failed pull after the group's backoff, then
// doubles it, up to a third of an epoch.
func (k *Keyring) backOffLocked(key groupKey, g *held) {
	k.storeLocked(key, g)
	k.wakeInLocked(key, g, g.backoff)
	g.backoff = min(g.backoff*2, max(g.rotation/3, firstBackoffMs))
}

// wakeInLocked replaces the group's pending re-pull with one in delayMs: a
// wake-up already on its way names an older generation and does nothing.
func (k *Keyring) wakeInLocked(key groupKey, g *held, delayMs int64) {
	stopTimer(g)
	if k.closed {
		return
	}
	g.wake++
	wake := g.wake
	g.stop = k.opts.AfterFunc(time.Duration(delayMs)*time.Millisecond, func() { k.repull(key, wake) })
}

func stopTimer(g *held) {
	if g.stop != nil {
		g.stop()
		g.stop = nil
	}
}

// repull is a group's scheduled pull of its current epoch.
func (k *Keyring) repull(key groupKey, wake uint64) {
	k.pullMu.Lock()
	defer k.pullMu.Unlock()
	k.mu.Lock()
	g, ok := k.groups[key]
	if !ok || g.wake != wake || k.closed {
		k.mu.Unlock()
		return
	}
	k.mu.Unlock()
	reply, err := k.pull(context.Background(), key, g, CurrentRequest(key.prefix))
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, still := k.groups[key]; !still || k.closed {
		return
	}
	if err != nil {
		k.backOffLocked(key, g)
		return
	}
	g.merge(reply)
	k.scheduleLocked(key, g)
}
