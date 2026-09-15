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
	wg.Go(func() {
		for n := range int64(rounds) {
			clock.set(issuerT0 + (n+1)*StatementEvery.Milliseconds())
			if err := issuer.Tick(); err != nil {
				t.Errorf("Tick: %v", err)
			}
		}
	})
	for range 2 {
		wg.Go(func() {
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
		})
	}
	wg.Wait()
}
