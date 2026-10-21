package identity

import (
	"sync"
	"testing"
)

// ConnectMaterial, Subscribe and unsubscribing are safe beside Tick and beside
// each other. Under the race detector this test checks that.
func TestTheIssuerIsSafeToUseWhileItTicks(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	const rounds = 16

	var wg sync.WaitGroup
	wg.Go(func() { tickThroughTheRounds(t, issuer, clock, rounds) })
	for range 2 {
		wg.Go(func() { subscribeThroughTheRounds(t, issuer, rounds) })
	}
	wg.Wait()
}

// tickThroughTheRounds moves the clock a statement's interval each round and
// ticks the issuer, so it issues new statements beside its readers.
func tickThroughTheRounds(t *testing.T, issuer *StatementIssuer, clock *testClock, rounds int) {
	t.Helper()
	for n := range int64(rounds) {
		clock.set(issuerT0 + (n+1)*StatementEvery.Milliseconds())
		if err := issuer.Tick(); err != nil {
			t.Errorf("Tick: %v", err)
		}
	}
}

// subscribeThroughTheRounds connects, subscribes and unsubscribes each round,
// reading the statement the issuer has pending for the subscription.
func subscribeThroughTheRounds(t *testing.T, issuer *StatementIssuer, rounds int) {
	t.Helper()
	for range rounds {
		material, err := issuer.ConnectMaterial()
		if err != nil {
			t.Errorf("ConnectMaterial: %v", err)
			return
		}
		ch, unsubscribe, err := issuer.Subscribe(bindingHashOf(material.Binding))
		if err != nil {
			t.Errorf("Subscribe: %v", err)
			return
		}
		pendingStatement(ch)
		unsubscribe()
	}
}
