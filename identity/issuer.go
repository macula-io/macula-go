package identity

import (
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

// ErrUnknownBinding is a subscription to a binding the issuer does not hold,
// or no longer holds.
var ErrUnknownBinding = errors.New("identity: no binding in force has that hash")

// ConnectMaterial is what a new dial carries: the CONNECT key, its binding, and
// the newest status statement for that binding.
type ConnectMaterial struct {
	Key     *NodeKey
	Binding SignedTBS
	Status  SignedTBS
}

// StatementIssuer is a client's status statement issuer, the client side of
// macula's macula_statement_issuer (D22). It holds the identity key and the
// node's CONNECT keys, a binding for each, and the newest status statement for
// each binding. At every Tick it issues a statement valid for StatementValid
// for each binding whose not_after has not passed, and hands it to that
// binding's subscribers. Every ConnectRotateEvery it rotates the CONNECT key:
// the new key's binding and statement exist before ConnectMaterial hands the
// key out, and the rotated-out binding keeps its statements until its
// not_after. Nothing is written to disk, so a new issuer starts with a new
// CONNECT key.
type StatementIssuer struct {
	mu          sync.Mutex
	identity    *NodeKey
	clock       func() int64
	current     [48]byte
	bindings    map[[48]byte]*statedBinding
	subscribers map[[48]byte][]*statementSubscription
}

// statedBinding is a CONNECT binding the issuer holds, with its key and its
// newest statement.
type statedBinding struct {
	key       *NodeKey
	binding   SignedTBS
	statement SignedTBS
	issuedAt  int64
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

// ConnectMaterial is the current CONNECT key with its binding and newest
// statement, for a new dial.
func (i *StatementIssuer) ConnectMaterial() ConnectMaterial {
	i.mu.Lock()
	defer i.mu.Unlock()
	current := i.bindings[i.current]
	return ConnectMaterial{Key: current.key, Binding: current.binding, Status: current.statement}
}

// Subscribe hands over the newest statement for the binding whose tbs hashes to
// bindingHash at every reissue. The channel holds at most one statement, the
// newest, and closes when the binding's not_after passes or unsubscribe runs,
// which may run more than once.
func (i *StatementIssuer) Subscribe(bindingHash [48]byte) (<-chan SignedTBS, func(), error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if _, held := i.bindings[bindingHash]; !held {
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

// Tick runs the periodic work at the clock's time: it drops the bindings past
// their not_after and closes their subscribers' channels, reissues a statement
// for each binding still held, and rotates the CONNECT key when it is due, or
// when its binding was dropped because ticks were missed.
func (i *StatementIssuer) Tick() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	now := i.clock()
	i.dropExpired(now)
	if err := i.reissue(now); err != nil {
		return err
	}
	if current, held := i.bindings[i.current]; !held || now >= current.issuedAt+ConnectRotateEvery.Milliseconds() {
		return i.rotateConnect(now)
	}
	return nil
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

func (i *StatementIssuer) dropExpired(now int64) {
	for hash, held := range i.bindings {
		if held.notAfter >= now {
			continue
		}
		delete(i.bindings, hash)
		for _, sub := range i.subscribers[hash] {
			sub.closed = true
			close(sub.ch)
		}
		delete(i.subscribers, hash)
	}
}

func (i *StatementIssuer) reissue(now int64) error {
	for hash, held := range i.bindings {
		statement, err := StatusStatement(i.identity, held.binding, now, now+StatementValid.Milliseconds())
		if err != nil {
			return err
		}
		held.statement = statement
		for _, sub := range i.subscribers[hash] {
			sub.deliver(statement)
		}
	}
	return nil
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
// becomes the current one.
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
	hash := sha512.Sum384(binding.TBS)
	i.bindings[hash] = &statedBinding{key: key, binding: binding, statement: statement, issuedAt: now, notAfter: notAfter}
	i.current = hash
	return nil
}
