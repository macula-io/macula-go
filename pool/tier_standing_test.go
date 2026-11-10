package pool

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/teststation"
)

// Standing registrations are state, not traffic: they go on every link of both
// tiers (macula#201 §2), and that is what lets two nodes on different tiers
// still reach each other. A subscription taken while the public tier is up
// therefore still hears a publication from a node whose only link is the
// fallback station (§9 scenarios 2 and 5).
func TestASubscriptionIsOnBothTiersAndHearsTheOtherOne(t *testing.T) {
	public, fallback, realm := tiers(t)
	subscriber := connectTiered(t, "tier subscriber", realm,
		[]*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(subscriber) == 2 })
	if got := subscriber.ActiveTier(); got != TierPublic {
		t.Fatalf("both tiers up: the active tier is %v, want TierPublic", got)
	}
	sub, err := subscriber.Subscribe(realm.ID, topic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	eventually(t, "subscribed on both tiers", func() bool {
		return public.Subscribed(subscriber.NodeID(), realm.ID, topic) &&
			fallback.Subscribed(subscriber.NodeID(), realm.ID, topic)
	})
	// The publisher's public tier is down, so everything it sends goes to the
	// fallback station: the one the subscriber's subscription has to be at too.
	publisher := connect(t, "fallback publisher", realm, fallback)
	say(t, publisher, realm, "from the fallback tier")
	if got := delivered(sub, 2*time.Second); len(got) != 1 {
		t.Errorf("%d deliveries, want 1: a subscription on the active tier alone never hears the other tier", len(got))
	}
}

// A served procedure is standing state too: a provider whose public tier is up
// is still advertised on its fallback link, so a caller linked only to the
// fallback station reaches it (§9 scenarios 2 and 5).
func TestAServedProcedureIsOnBothTiersAndAnswersTheOtherOne(t *testing.T) {
	public, fallback, realm := tiers(t)
	providerID := nodeIDOf(t, "tier provider")
	realm.Admit(t, public, providerID)
	realm.Admit(t, fallback, providerID)
	provider := connectTiered(t, "tier provider", realm,
		[]*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(provider) == 2 })
	served, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	t.Cleanup(func() { _ = served.Stop() })
	eventually(t, "advertised on both tiers", func() bool {
		return public.Advertised(realm.ID, procedure) && fallback.Advertised(realm.ID, procedure)
	})
	// A caller whose only link is the fallback station resolves the procedure
	// through the advertisement that station holds.
	caller := connect(t, "fallback caller", realm, fallback)
	answer, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello")})
	if err != nil {
		t.Fatalf("a call from a caller linked only to the fallback: %v", err)
	}
	if text, _ := answer.AsText(); text != "hello" {
		t.Errorf("the call answered %q, want %q", text, "hello")
	}
}
