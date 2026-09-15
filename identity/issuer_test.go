package identity

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
)

const issuerT0 = int64(1789000000000)

// testClock is a clock the test moves.
type testClock struct{ now atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.now.Store(issuerT0)
	return c
}

func (c *testClock) read() int64  { return c.now.Load() }
func (c *testClock) set(ms int64) { c.now.Store(ms) }

func bindingHashOf(s SignedTBS) [48]byte { return sha512.Sum384(s.TBS) }

func newIssuer(t *testing.T, key *NodeKey, clock *testClock) *StatementIssuer {
	t.Helper()
	issuer, err := NewStatementIssuer(key, clock.read)
	if err != nil {
		t.Fatalf("NewStatementIssuer: %v", err)
	}
	return issuer
}

func tickAt(t *testing.T, issuer *StatementIssuer, clock *testClock, ms int64) {
	t.Helper()
	clock.set(ms)
	if err := issuer.Tick(); err != nil {
		t.Fatalf("Tick at %d: %v", ms, err)
	}
}

// delivery is what a subscriber's channel holds right now.
type delivery int

const (
	statementPending delivery = iota
	nothingPending
	channelClosed
)

// pendingStatement is what ch holds, without waiting.
func pendingStatement(ch <-chan SignedTBS) (SignedTBS, delivery) {
	select {
	case s, open := <-ch:
		if !open {
			return SignedTBS{}, channelClosed
		}
		return s, statementPending
	default:
		return SignedTBS{}, nothingPending
	}
}

func subscribed(t *testing.T, issuer *StatementIssuer, binding SignedTBS) (<-chan SignedTBS, func()) {
	t.Helper()
	ch, unsubscribe, err := issuer.Subscribe(bindingHashOf(binding))
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	return ch, unsubscribe
}

// checkStatementAt fails t unless statement keeps binding in force at ms and
// expires an hour later.
func checkStatementAt(t *testing.T, statement, binding SignedTBS, identity *NodeKey, ms int64) {
	t.Helper()
	expiresAt, err := VerifyStatus(statement, binding, identity.PublicKey(), identity.Profile(), ms)
	if err != nil || expiresAt != ms+hourMs {
		t.Fatalf("at %d: the statement verifies as (%d, %v), want it to expire an hour on", ms, expiresAt, err)
	}
}

// reissuedAt ticks at ms and checks that the subscriber holds a statement for
// binding that verifies there and expires an hour later.
func reissuedAt(t *testing.T, issuer *StatementIssuer, clock *testClock, ch <-chan SignedTBS, binding SignedTBS, identity *NodeKey, ms int64) {
	t.Helper()
	tickAt(t, issuer, clock, ms)
	statement, got := pendingStatement(ch)
	if got != statementPending {
		t.Fatalf("at %d: the subscriber holds no statement (%d)", ms, got)
	}
	checkStatementAt(t, statement, binding, identity, ms)
}

func TestConnectMaterialIsBoundAndStatedFromTheStart(t *testing.T) {
	forEachProfile(t, func(t *testing.T, p profile.Profile, keys bindingKeys) {
		material := newIssuer(t, keys.identity, newTestClock()).ConnectMaterial()
		if material.Key.Purpose() != PurposeConnect || material.Key.Profile() != p {
			t.Fatalf("the CONNECT key is a %s key, want a %s CONNECT key", material.Key, p)
		}
		info, err := VerifyConnectBinding(material.Binding, keys.identity.PublicKey(), p, material.Key.PublicKey(), issuerT0)
		if err != nil || info.NotAfter != issuerT0+7*dayMs {
			t.Errorf("the CONNECT binding verifies as (%+v, %v), want it valid for 7 days", info, err)
		}
		checkStatementAt(t, material.Status, material.Binding, keys.identity, issuerT0)
	})
}

func TestAStatementIsReissuedEvery15MinutesAndValidForAnHour(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := issuer.ConnectMaterial().Binding
	ch, _ := subscribed(t, issuer, binding)
	reissuedAt(t, issuer, clock, ch, binding, identity, issuerT0+15*minuteMs)
	reissuedAt(t, issuer, clock, ch, binding, identity, issuerT0+30*minuteMs)
	// A new dial takes the newest statement too.
	checkStatementAt(t, issuer.ConnectMaterial().Status, binding, identity, issuerT0+30*minuteMs)
}

// A subscriber that has not read keeps only the newest statement: statements
// replace each other, and never wait for the reader.
func TestASubscriberThatFallsBehindHoldsOnlyTheNewestStatement(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := issuer.ConnectMaterial().Binding
	ch, _ := subscribed(t, issuer, binding)
	tickAt(t, issuer, clock, issuerT0+15*minuteMs)
	tickAt(t, issuer, clock, issuerT0+30*minuteMs)
	statement, got := pendingStatement(ch)
	if got != statementPending {
		t.Fatalf("the subscriber holds no statement (%d)", got)
	}
	checkStatementAt(t, statement, binding, identity, issuerT0+30*minuteMs)
	if _, got := pendingStatement(ch); got != nothingPending {
		t.Fatalf("the subscriber holds a second statement (%d), want only the newest", got)
	}
}

func TestTheConnectKeyRotatesEvery5DaysWithItsBindingAndStatementFirst(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	first := issuer.ConnectMaterial().Key.PublicKey()

	tickAt(t, issuer, clock, issuerT0+5*dayMs-1)
	if !bytes.Equal(issuer.ConnectMaterial().Key.PublicKey(), first) {
		t.Fatal("the CONNECT key rotated before 5 days")
	}
	rotation := issuerT0 + 5*dayMs
	tickAt(t, issuer, clock, rotation)
	material := issuer.ConnectMaterial()
	if bytes.Equal(material.Key.PublicKey(), first) {
		t.Fatal("the CONNECT key did not rotate at 5 days")
	}
	nodeID, _ := identity.NodeID()
	info, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), rotation)
	if err != nil || info != (BindingInfo{Use: BindingConnect, NodeID: nodeID, NotAfter: rotation + 7*dayMs}) {
		t.Fatalf("the new binding verifies as (%+v, %v), want it valid for 7 days from the rotation", info, err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, rotation)
}

func TestARotatedOutBindingKeepsItsStatementsUntilItsNotAfterAndNoneAfter(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	old := issuer.ConnectMaterial().Binding
	ch, _ := subscribed(t, issuer, old)

	reissuedAt(t, issuer, clock, ch, old, identity, issuerT0+5*dayMs)
	reissuedAt(t, issuer, clock, ch, old, identity, issuerT0+7*dayMs)
	tickAt(t, issuer, clock, issuerT0+7*dayMs+1)
	if _, got := pendingStatement(ch); got != channelClosed {
		t.Fatalf("after not_after the subscriber's channel is %d, want it closed", got)
	}
	if _, _, err := issuer.Subscribe(bindingHashOf(old)); !errors.Is(err, ErrUnknownBinding) {
		t.Fatalf("Subscribe to a binding past its not_after: %v, want ErrUnknownBinding", err)
	}
}

// Nothing is kept across issuers: a new one starts with a new CONNECT key.
func TestANewIssuerStartsWithANewConnectBinding(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	first := newIssuer(t, identity, newTestClock()).ConnectMaterial().Binding
	second := newIssuer(t, identity, newTestClock())
	if bindingHashOf(second.ConnectMaterial().Binding) == bindingHashOf(first) {
		t.Fatal("a new issuer reuses the old binding")
	}
	if _, _, err := second.Subscribe(bindingHashOf(first)); !errors.Is(err, ErrUnknownBinding) {
		t.Fatalf("Subscribe to another issuer's binding: %v, want ErrUnknownBinding", err)
	}
}

func TestTheIssuerTakesOnlyAnIdentityKey(t *testing.T) {
	keys := keysFor(t, profile.PQPure)
	if _, err := NewStatementIssuer(keys.connect, newTestClock().read); !errors.Is(err, ErrNotAnIdentityKey) {
		t.Fatalf("NewStatementIssuer with a CONNECT key: %v, want ErrNotAnIdentityKey", err)
	}
}

func TestUnsubscribingClosesTheChannelAndStopsStatements(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	ch, unsubscribe := subscribed(t, issuer, issuer.ConnectMaterial().Binding)
	unsubscribe()
	if _, got := pendingStatement(ch); got != channelClosed {
		t.Fatalf("after unsubscribing the channel is %d, want it closed", got)
	}
	tickAt(t, issuer, clock, issuerT0+15*minuteMs)
	unsubscribe()
}

func TestRunEveryTicksOnEachTickUntilItsContextEnds(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := issuer.ConnectMaterial().Binding
	ch, _ := subscribed(t, issuer, binding)

	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		issuer.RunEvery(ctx, ticks, func(err error) { t.Errorf("tick: %v", err) })
		close(done)
	}()

	clock.set(issuerT0 + 15*minuteMs)
	ticks <- time.Now()
	select {
	case statement := <-ch:
		checkStatementAt(t, statement, binding, identity, issuerT0+15*minuteMs)
	case <-time.After(5 * time.Second):
		t.Fatal("no statement after a tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("RunEvery did not return after its context ended")
	}
}

// An issuer that missed every tick until after its binding's not_after, as a
// laptop asleep for a week does, drops that binding and rotates to a new
// CONNECT key at its next tick, so a new dial never carries an expired binding.
func TestAnIssuerThatMissedItsTicksRotatesToANewBindingAtTheNextOne(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	old := issuer.ConnectMaterial()
	ch, _ := subscribed(t, issuer, old.Binding)

	late := issuerT0 + 7*dayMs + 1
	tickAt(t, issuer, clock, late)
	if _, got := pendingStatement(ch); got != channelClosed {
		t.Fatalf("the expired binding's subscriber channel is %d, want it closed", got)
	}
	material := issuer.ConnectMaterial()
	if bytes.Equal(material.Key.PublicKey(), old.Key.PublicKey()) {
		t.Fatal("a new dial still takes the CONNECT key whose binding expired")
	}
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), late); err != nil {
		t.Fatalf("the new CONNECT binding: %v", err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, late)
}
