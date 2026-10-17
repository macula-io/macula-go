package identity

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// issuedAtOf is the issued_at a status statement's tbs names.
func issuedAtOf(t *testing.T, statement SignedTBS) int64 {
	t.Helper()
	fields, err := cbor.Decode(statement.TBS)
	if err != nil {
		t.Fatalf("a statement's tbs: %v", err)
	}
	v, _ := fields.Get("issued_at")
	n, ok := protocolInt(v)
	if !ok {
		t.Fatal("a statement without an integer issued_at")
	}
	return n
}

// pushedAt ticks at ms and returns the statement the subscriber holds.
func pushedAt(t *testing.T, issuer *StatementIssuer, clock *testClock, ch <-chan SignedTBS, ms int64) SignedTBS {
	t.Helper()
	tickAt(t, issuer, clock, ms)
	statement, got := pendingStatement(ch)
	if got != statementPending {
		t.Fatalf("at %d: the subscriber holds no statement (%d)", ms, got)
	}
	return statement
}

// A peer drops a statement that is not newer than the last it accepted on a
// connection (macula 15.5.0's status_not_newer), so after the clock stepped
// back within the tolerance a statement pushed for a binding is issued a
// millisecond after the one before it, as macula_statement_issuer does
// (macula-architecture#22).
func TestAClockSteppedBackWithinTheToleranceStillPushesANewerStatement(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)

	before := issuedAtOf(t, pushedAt(t, issuer, clock, ch, issuerT0+30*minuteMs))
	stepped := issuerT0 + 26*minuteMs
	pushed := pushedAt(t, issuer, clock, ch, stepped)
	if got := issuedAtOf(t, pushed); got != before+1 {
		t.Fatalf("after the clock stepped back 4 minutes the statement is issued at %d, want %d, a millisecond after the last", got, before+1)
	}
	if expiresAt, err := VerifyStatus(pushed, binding, identity.PublicKey(), identity.Profile(), stepped); err != nil || expiresAt != before+1+hourMs {
		t.Fatalf("at %d: the statement verifies as (%d, %v), want it to expire an hour after it was issued", stepped, expiresAt, err)
	}
	// Once the clock passes the last statement, statements follow it again.
	later := issuerT0 + 50*minuteMs
	if got := issuedAtOf(t, pushedAt(t, issuer, clock, ch, later)); got != later {
		t.Fatalf("with the clock past the last statement it is issued at %d, want %d", got, later)
	}
}

// A statement a millisecond after the last would be dated past the tolerance
// once the clock stepped back further, and a peer closes the link on a
// statement dated that far ahead (macula 15.6.0, macula#110). The issuer
// states the binding at its clock instead; a connection that accepted the
// later statement drops this one as not newer and stays up.
func TestAClockSteppedBackPastTheTolerancePushesAStatementAtItsClock(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)

	pushedAt(t, issuer, clock, ch, issuerT0+30*minuteMs)
	// 20 minutes back: past the tolerance, but not before the binding, so the
	// CONNECT key stays.
	stepped := issuerT0 + 10*minuteMs
	pushed := pushedAt(t, issuer, clock, ch, stepped)
	if got := issuedAtOf(t, pushed); got != stepped {
		t.Fatalf("after the clock stepped back 20 minutes the statement is issued at %d, want %d, the clock", got, stepped)
	}
	checkStatementAt(t, pushed, binding, identity, stepped)
}

// A new dial has no earlier statement to be newer than, so after the clock
// stepped back past the tolerance it carries a statement at the clock's time,
// which verifies there. The dial reissues the binding's statement first, as
// it is due, and that push is at the clock too, not a millisecond after the
// last: a connection that accepted the last drops it as not newer and stays
// up. The next push is newer than the dial's and in force.
func TestANewDialAfterTheClockSteppedBackCarriesAStatementInForce(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)
	pushedAt(t, issuer, clock, ch, issuerT0+30*minuteMs)

	stepped := issuerT0 + 10*minuteMs
	clock.set(stepped)
	material := currentMaterial(t, issuer)
	checkStatementAt(t, material.Status, material.Binding, identity, stepped)
	if pushed, got := pendingStatement(ch); got == statementPending && issuedAtOf(t, pushed) != stepped {
		t.Fatalf("on the new dial a subscriber was handed a statement at %d, want it at the clock, %d", issuedAtOf(t, pushed), stepped)
	}

	next := stepped + 15*minuteMs
	pushed := pushedAt(t, issuer, clock, ch, next)
	if got := issuedAtOf(t, pushed); got <= stepped {
		t.Fatalf("the next push is issued at %d, want it after the new dial's, %d", got, stepped)
	}
	checkStatementAt(t, pushed, binding, identity, next)
}
