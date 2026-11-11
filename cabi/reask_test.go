package main

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// A connect whose seeds never answer reports a timeout, not a failure: the
// pool's own ErrNoLink is joined with the context's error, so classifying it
// ahead of the context would change every connect's kind (macula-go#76).
func TestAConnectWithNoAnsweringSeedIsATimeout(t *testing.T) {
	f := newFleet(t, "abi connect timeout")
	for _, s := range f.stations {
		s.Refuse(20 * time.Second)
	}
	options := `{"timeout_ms": 500}`
	_, err := connect(context.Background(), teststation.Key(t, profile.PQPure, "abi connect timeout caller"),
		f.seedsJSON(f.stations...), options)
	if got := classify(nil, err); got.kind != kindTimeout {
		t.Errorf("a connect with no answering seed: %s (%v), want timeout", got.kind, err)
	}
}

// A lookup that failed is a timeout under an unbounded context too: the call
// joins it with its own deadline, so a binding reads the same kind whether or
// not it passed timeout_ms (cabi/cancel.go makes timeout_ms 0 unbounded).
func TestAFailedLookupUnderAnUnboundedContextIsATimeout(t *testing.T) {
	f := newFleet(t, "abi unbounded lookup")
	lp := f.join(t, "abi unbounded caller", f.stations[0])
	procedure := ownProcedure(lp, "never")
	// No station left to answer the lookup at all: every round fails with
	// ErrNoLink, which is the latest failed lookup the call concludes with.
	for _, s := range f.stations {
		s.Stop()
	}
	ctx, cancel, err := callContext(0, 0)
	if err != nil {
		t.Fatalf("callContext: %v", err)
	}
	defer cancel()
	_, err = call(ctx, lp.pool, f.realm.ID, procedure, `null`, 0, callOptions{})
	if got := classify(ctx, err); got.kind != kindTimeout {
		t.Errorf("a failed lookup at timeout_ms 0: %s (%v), want timeout", got.kind, err)
	}
}
