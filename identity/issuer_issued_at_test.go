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
// connection (macula 15.5.0's status_not_newer), so each statement pushed for
// a binding is issued after the one before it, a millisecond after it when the
// clock has stepped back, as macula_statement_issuer does
// (macula-architecture#22).
func TestAStatementPushedAfterTheClockSteppedBackIsStillNewer(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)

	before := issuedAtOf(t, pushedAt(t, issuer, clock, ch, issuerT0+30*minuteMs))
	// 20 minutes back: past the tolerance, so the statement is due again, but
	// not before the binding, so the CONNECT key stays.
	stepped := issuedAtOf(t, pushedAt(t, issuer, clock, ch, issuerT0+10*minuteMs))
	if stepped != before+1 {
		t.Fatalf("after the clock stepped back the statement is issued at %d, want %d, a millisecond after the last", stepped, before+1)
	}
	// Once the clock passes the last statement, statements follow it again.
	later := issuerT0 + 50*minuteMs
	if got := issuedAtOf(t, pushedAt(t, issuer, clock, ch, later)); got != later {
		t.Fatalf("with the clock past the last statement it is issued at %d, want %d", got, later)
	}
}

// A new dial has no earlier statement to be newer than, so after the clock
// stepped back past the tolerance it carries a statement at the clock's time,
// which verifies there, while statements pushed on connections stay newer than
// every statement issued for the binding, the new dial's included.
func TestANewDialAfterTheClockSteppedBackCarriesAStatementInForce(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	binding := currentMaterial(t, issuer).Binding
	ch, _ := subscribed(t, issuer, binding)
	last := issuedAtOf(t, pushedAt(t, issuer, clock, ch, issuerT0+30*minuteMs))

	stepped := issuerT0 + 10*minuteMs
	clock.set(stepped)
	material := currentMaterial(t, issuer)
	checkStatementAt(t, material.Status, material.Binding, identity, stepped)
	if pushed, got := pendingStatement(ch); got == statementPending && issuedAtOf(t, pushed) <= last {
		t.Fatalf("a subscriber was handed a statement at %d after one at %d", issuedAtOf(t, pushed), last)
	}

	if got := issuedAtOf(t, pushedAt(t, issuer, clock, ch, stepped+16*minuteMs)); got <= last {
		t.Fatalf("the next push is issued at %d, want it after the last pushed, %d", got, last)
	}
}
