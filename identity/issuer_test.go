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
		material := currentMaterial(t, newIssuer(t, keys.identity, newTestClock()))
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
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)
	reissuedAt(t, issuer, clock, ch, binding, identity, issuerT0+15*minuteMs)
	reissuedAt(t, issuer, clock, ch, binding, identity, issuerT0+30*minuteMs)
	// A new dial takes the newest statement too.
	checkStatementAt(t, currentMaterial(t, issuer).Status, binding, identity, issuerT0+30*minuteMs)
}

// A subscriber that has not read keeps only the newest statement: statements
// replace each other, and never wait for the reader.
func TestASubscriberThatFallsBehindHoldsOnlyTheNewestStatement(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
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
	first := currentMaterial(t, issuer).Key.PublicKey()

	tickAt(t, issuer, clock, issuerT0+5*dayMs-1)
	if !bytes.Equal(currentMaterial(t, issuer).Key.PublicKey(), first) {
		t.Fatal("the CONNECT key rotated before 5 days")
	}
	rotation := issuerT0 + 5*dayMs
	tickAt(t, issuer, clock, rotation)
	material := currentMaterial(t, issuer)
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
	old := currentMaterial(t, issuer).Binding
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
	first := currentMaterial(t, newIssuer(t, identity, newTestClock())).Binding
	second := newIssuer(t, identity, newTestClock())
	if bindingHashOf(currentMaterial(t, second).Binding) == bindingHashOf(first) {
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
	ch, unsubscribe := subscribed(t, issuer, currentMaterial(t, issuer).Binding)
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
	binding := currentMaterial(t, issuer).Binding
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
	old := currentMaterial(t, issuer)
	ch, _ := subscribed(t, issuer, old.Binding)

	late := issuerT0 + 7*dayMs + 1
	tickAt(t, issuer, clock, late)
	if _, got := pendingStatement(ch); got != channelClosed {
		t.Fatalf("the expired binding's subscriber channel is %d, want it closed", got)
	}
	material := currentMaterial(t, issuer)
	if bytes.Equal(material.Key.PublicKey(), old.Key.PublicKey()) {
		t.Fatal("a new dial still takes the CONNECT key whose binding expired")
	}
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), late); err != nil {
		t.Fatalf("the new CONNECT binding: %v", err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, late)
}

// An issuer whose clock reads a time nothing can be issued at fails its tick
// and ConnectMaterial, without panicking or handing out a binding past its
// not_after, and is whole again at its next tick at a time it can issue at.
func TestAnIssuerRecoversFromATimeItCannotIssueAt(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)

	clock.set(maxProtocolInt - 1)
	if err := issuer.Tick(); err == nil {
		t.Fatal("Tick at 2^53-1 succeeded, want an error")
	}
	if _, err := materialOf(t, issuer); !errors.Is(err, ErrNoConnectMaterial) {
		t.Fatalf("ConnectMaterial at 2^53-1: %v, want ErrNoConnectMaterial", err)
	}

	later := issuerT0 + 7*dayMs + minuteMs
	tickAt(t, issuer, clock, later)
	material := currentMaterial(t, issuer)
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), later); err != nil {
		t.Fatalf("the CONNECT binding after the issuer recovered: %v", err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, later)
}

// ConnectMaterial is in force at the clock's time even when no Tick ran since
// the clock moved, as after a sleep or a clock step: it reissues the statement,
// or rotates the key, first.
func TestConnectMaterialIsInForceWhenTheClockMovedWithoutATick(t *testing.T) {
	jumps := map[string]int64{
		"2 hours on":         2 * hourMs,
		"7 days and 1 ms on": 7*dayMs + 1,
		"an hour back":       -hourMs,
	}
	for name, jump := range jumps {
		t.Run(name, func(t *testing.T) {
			identity := sharedKey(t, pureIdentityKey)
			clock := newTestClock()
			issuer := newIssuer(t, identity, clock)
			now := issuerT0 + jump
			clock.set(now)
			material := currentMaterial(t, issuer)
			if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), now); err != nil {
				t.Errorf("the CONNECT binding at the clock's time: %v", err)
			}
			checkStatementAt(t, material.Status, material.Binding, identity, now)
		})
	}
}

// At a rotation the issuer lets go of the rotated-out CONNECT key: the binding
// it keeps until its not_after no longer holds that key.
func TestARotationLetsGoOfTheRotatedOutKey(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	old := bindingHashOf(currentMaterial(t, issuer).Binding)
	tickAt(t, issuer, clock, issuerT0+5*dayMs)

	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	held := issuer.bindings[old]
	if held == nil || held.key != nil {
		t.Fatalf("the rotated-out binding: held %t, key kept %t; want it held without its key", held != nil, held != nil && held.key != nil)
	}
}

// The binding and statement ConnectMaterial hands out are the caller's own:
// changing their bytes changes nothing the issuer holds.
func TestConnectMaterialHandsOutCopies(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	issuer := newIssuer(t, identity, newTestClock())
	first := currentMaterial(t, issuer)
	first.Binding.TBS[0] ^= 0xff
	first.Status.Signature[0] ^= 0xff

	material := currentMaterial(t, issuer)
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), issuerT0); err != nil {
		t.Errorf("the binding after a caller changed its copy: %v", err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, issuerT0)
}

// A statement a subscriber receives is its own: changing its bytes changes
// nothing the issuer holds or hands out next.
func TestADeliveredStatementIsTheSubscribersOwnCopy(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)
	tickAt(t, issuer, clock, issuerT0+15*minuteMs)
	delivered, got := pendingStatement(ch)
	if got != statementPending {
		t.Fatalf("the subscriber holds no statement (%d)", got)
	}
	delivered.Signature[0] ^= 0xff

	checkStatementAt(t, currentMaterial(t, issuer).Status, binding, identity, issuerT0+15*minuteMs)
}

// A CONNECT key rotation that keeps failing is counted, and a tick reports it
// as ErrRotationOverdue once the current binding expires within
// RotationMargin. Until its not_after, the binding and a fresh statement still
// serve dials.
func TestARotationThatKeepsFailingIsCountedAndEscalatesBeforeTheBindingExpires(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	// An issuer this close to 2^53 can still issue an hour's statement, but a
	// rotation's 7-day binding would end at 2^53 or later, which no verifier
	// accepts, so every rotation fails.
	start := int64(maxProtocolInt) - 7*dayMs - 1
	clock := newTestClock()
	clock.set(start)
	issuer := newIssuer(t, identity, clock)
	notAfter := start + 7*dayMs

	before := []int64{start + 5*dayMs, start + 5*dayMs + 15*minuteMs, notAfter - dayMs}
	for n, at := range before {
		clock.set(at)
		if err := issuer.Tick(); err == nil || errors.Is(err, ErrRotationOverdue) {
			t.Fatalf("tick %d, %d ms before not_after: %v, want an ordinary rotation error", n+1, notAfter-at, err)
		}
		if got := issuer.RotationFailures(); got != uint64(n+1) {
			t.Fatalf("after tick %d, %d rotation failures counted, want %d", n+1, got, n+1)
		}
	}

	inMargin := notAfter - dayMs + 1
	clock.set(inMargin)
	if err := issuer.Tick(); !errors.Is(err, ErrRotationOverdue) {
		t.Fatalf("a tick less than 24 h before not_after: %v, want ErrRotationOverdue", err)
	}
	if got := issuer.RotationFailures(); got != uint64(len(before)+1) {
		t.Fatalf("%d rotation failures counted, want %d", got, len(before)+1)
	}
	material := currentMaterial(t, issuer)
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), inMargin); err != nil {
		t.Fatalf("the CONNECT binding inside the margin: %v", err)
	}
	checkStatementAt(t, material.Status, material.Binding, identity, inMargin)
}
