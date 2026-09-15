package identity

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"sync"
	"time"
)

// The timings of a client's status statements and CONNECT bindings (D22).
const (
	// StatementEvery is how often Run reissues status statements.
	StatementEvery = 15 * time.Minute
	// StatementValid is how long a status statement is valid.
	StatementValid = time.Hour
	// ConnectBindingValid is how long a CONNECT binding is valid.
	ConnectBindingValid = 7 * 24 * time.Hour
	// ConnectRotateEvery is how often the CONNECT key rotates.
	ConnectRotateEvery = 5 * 24 * time.Hour
)

var (
	// ErrUnknownBinding is a subscription to a binding the issuer does not
	// hold, or whose not_after has passed.
	ErrUnknownBinding = errors.New("identity: no binding in force has that hash")
	// ErrNoConnectMaterial is a request for connect material at a time when the
	// issuer holds no CONNECT binding and status statement in force, because the
	// work that renews them failed.
	ErrNoConnectMaterial = errors.New("identity: no CONNECT binding and status statement in force")
)

// ConnectMaterial is what a new dial carries: the CONNECT key, its binding, and
// a status statement for that binding.
type ConnectMaterial struct {
	Key     *NodeKey
	Binding SignedTBS
	Status  SignedTBS
}

// StatementIssuer is a client's status statement issuer, the client side of
// macula's macula_statement_issuer (D22). It holds the identity key, the node's
// CONNECT bindings with the newest status statement for each, and the current
// CONNECT key. At every Tick it issues a statement valid for StatementValid for
// each binding whose not_after has not passed, and hands it to that binding's
// subscribers. Every ConnectRotateEvery it rotates the CONNECT key: the new
// key's binding and statement exist before ConnectMaterial hands the key out,
// the rotated-out binding keeps its statements until its not_after, and the
// issuer lets go of the rotated-out key. ConnectMaterial does work that is due
// itself, so a dial after missed ticks, a sleep or a clock step still carries
// material in force. Nothing is written to disk, so a new issuer starts with a
// new CONNECT key.
type StatementIssuer struct {
	mu          sync.Mutex
	identity    *NodeKey
	clock       func() int64
	current     [48]byte
	bindings    map[[48]byte]*statedBinding
	subscribers map[[48]byte][]*statementSubscription
}

// statedBinding is a CONNECT binding the issuer holds, with its newest
// statement, and its key while it is the current binding.
type statedBinding struct {
	key       *NodeKey
	binding   SignedTBS
	statement SignedTBS
	boundAt   int64
	statedAt  int64
	notAfter  int64
}

// statementSubscription is a subscriber's channel, which holds at most the
// newest statement.
type statementSubscription struct {
	ch     chan SignedTBS
	closed bool
}

// NewStatementIssuer is an issuer for identityKey that reads the time, in
// milliseconds, from clock, or from the wall clock when clock is nil. It starts
// with a new CONNECT key, bound and stated.
func NewStatementIssuer(identityKey *NodeKey, clock func() int64) (*StatementIssuer, error) {
	if _, err := identityKey.NodeID(); err != nil {
		return nil, err
	}
	if clock == nil {
		clock = func() int64 { return time.Now().UnixMilli() }
	}
	issuer := &StatementIssuer{
		identity:    identityKey,
		clock:       clock,
		bindings:    map[[48]byte]*statedBinding{},
		subscribers: map[[48]byte][]*statementSubscription{},
	}
	if err := issuer.rotateConnect(clock()); err != nil {
		return nil, err
	}
	return issuer, nil
}

// ConnectMaterial is the current CONNECT key with its binding and a statement
// for it, both in force at the clock's time, for a new dial. When a statement
// or a rotation is due, because ticks were missed or the clock moved, it does
// Tick's work first. It returns ErrNoConnectMaterial, with the errors of that
// work, rather than a binding or statement out of force. The binding and
// statement are the caller's own copies.
func (i *StatementIssuer) ConnectMaterial() (ConnectMaterial, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock()
	var workErr error
	if held := i.bindings[i.current]; held.rotationDue(now) || held.restatementDue(now) {
		workErr = i.tick(now)
	}
	current := i.bindings[i.current]
	if !current.inForce(now) {
		return ConnectMaterial{}, errors.Join(ErrNoConnectMaterial, workErr)
	}
	return ConnectMaterial{Key: current.key, Binding: current.binding.clone(), Status: current.statement.clone()}, nil
}

// Subscribe hands over the newest statement for the binding whose tbs hashes to
// bindingHash at every reissue, as the subscriber's own copy. The channel holds
// at most one statement, the newest. It closes once a tick finds the binding's
// not_after passed, or when unsubscribe runs, which may run more than once. The
// subscriber owns the subscription: the issuer keeps it until then, so a
// subscriber that stops reading runs unsubscribe.
func (i *StatementIssuer) Subscribe(bindingHash [48]byte) (<-chan SignedTBS, func(), error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if held, ok := i.bindings[bindingHash]; !ok || held.notAfter < i.clock() {
		return nil, nil, ErrUnknownBinding
	}
	sub := &statementSubscription{ch: make(chan SignedTBS, 1)}
	i.subscribers[bindingHash] = append(i.subscribers[bindingHash], sub)
	return sub.ch, func() { i.unsubscribe(bindingHash, sub) }, nil
}

func (i *StatementIssuer) unsubscribe(bindingHash [48]byte, sub *statementSubscription) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if sub.closed {
		return
	}
	sub.closed = true
	close(sub.ch)
	subs := i.subscribers[bindingHash]
	for n, s := range subs {
		if s == sub {
			i.subscribers[bindingHash] = append(subs[:n], subs[n+1:]...)
			return
		}
	}
}

// Tick does the periodic work at the clock's time. It issues a statement for
// each binding whose not_after has not passed, and hands it to that binding's
// subscribers. It rotates the CONNECT key when ConnectRotateEvery has passed
// since the current binding, or the clock reads earlier than that binding.
// Then it lets go of the bindings past their not_after and closes their
// subscribers' channels, but keeps the current binding until a rotation has
// replaced it. It carries on past a failure and returns every error it met.
func (i *StatementIssuer) Tick() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.tick(i.clock())
}

func (i *StatementIssuer) tick(now int64) error {
	reissueErr := i.reissue(now)
	var rotateErr error
	if i.bindings[i.current].rotationDue(now) {
		rotateErr = i.rotateConnect(now)
	}
	i.dropExpired(now)
	return errors.Join(reissueErr, rotateErr)
}

// RunEvery calls Tick at every value from ticks until ctx ends, and hands a
// failed tick's error to onError when onError is not nil.
func (i *StatementIssuer) RunEvery(ctx context.Context, ticks <-chan time.Time, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			if err := i.Tick(); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// Run ticks every StatementEvery until ctx ends, as RunEvery does.
func (i *StatementIssuer) Run(ctx context.Context, onError func(error)) {
	ticker := time.NewTicker(StatementEvery)
	defer ticker.Stop()
	i.RunEvery(ctx, ticker.C, onError)
}

// dropExpired lets go of the bindings past their not_after at now and closes
// their subscribers' channels. The current binding stays held, out of force,
// until a rotation replaces it.
func (i *StatementIssuer) dropExpired(now int64) {
	for hash, held := range i.bindings {
		if held.notAfter >= now {
			continue
		}
		for _, sub := range i.subscribers[hash] {
			sub.closed = true
			close(sub.ch)
		}
		delete(i.subscribers, hash)
		if hash != i.current {
			delete(i.bindings, hash)
		}
	}
}

// reissue issues a statement at now for each binding whose not_after has not
// passed, and hands each subscriber its own copy. It carries on past a failure
// and returns every error it met.
func (i *StatementIssuer) reissue(now int64) error {
	var errs []error
	for hash, held := range i.bindings {
		if held.notAfter < now {
			continue
		}
		statement, err := StatusStatement(i.identity, held.binding, now, now+StatementValid.Milliseconds())
		if err != nil {
			errs = append(errs, err)
			continue
		}
		held.statement, held.statedAt = statement, now
		for _, sub := range i.subscribers[hash] {
			sub.deliver(statement.clone())
		}
	}
	return errors.Join(errs...)
}

// deliver puts statement in the channel in place of any statement not yet
// read. Only the issuer sends, under its lock, so the send never waits.
func (s *statementSubscription) deliver(statement SignedTBS) {
	select {
	case <-s.ch:
	default:
	}
	s.ch <- statement
}

// rotateConnect makes a new CONNECT key, and binds and states it before it
// becomes the current one. The binding it replaces keeps its statements, and
// the issuer lets go of that binding's key.
func (i *StatementIssuer) rotateConnect(now int64) error {
	key, err := GenerateKey(PurposeConnect, i.identity.profile)
	if err != nil {
		return err
	}
	notAfter := now + ConnectBindingValid.Milliseconds()
	binding, err := ConnectBinding(i.identity, key.PublicKey(), now, notAfter)
	if err != nil {
		return err
	}
	statement, err := StatusStatement(i.identity, binding, now, now+StatementValid.Milliseconds())
	if err != nil {
		return err
	}
	if previous, held := i.bindings[i.current]; held {
		previous.key = nil
	}
	hash := sha512.Sum384(binding.TBS)
	i.bindings[hash] = &statedBinding{key: key, binding: binding, statement: statement, boundAt: now, statedAt: now, notAfter: notAfter}
	i.current = hash
	return nil
}

// rotationDue reports whether the key of binding b is due to be replaced at
// now: ConnectRotateEvery has passed since b, or now is earlier than b.
func (b *statedBinding) rotationDue(now int64) bool {
	return now < b.boundAt || now >= b.boundAt+ConnectRotateEvery.Milliseconds()
}

// restatementDue reports whether b's statement is due to be reissued at now:
// StatementEvery has passed since it, or now is earlier than it.
func (b *statedBinding) restatementDue(now int64) bool {
	return now < b.statedAt || now >= b.statedAt+StatementEvery.Milliseconds()
}

// inForce reports whether b's binding and its statement are both valid at now.
func (b *statedBinding) inForce(now int64) bool {
	return b.boundAt <= now && now <= b.notAfter && b.statedAt <= now && now < b.statedAt+StatementValid.Milliseconds()
}

// clone is s with bytes of its own.
func (s SignedTBS) clone() SignedTBS {
	return SignedTBS{TBS: bytes.Clone(s.TBS), Signature: bytes.Clone(s.Signature)}
}
