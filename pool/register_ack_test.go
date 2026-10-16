package pool

import (
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// The pool's Serve and Subscribe return once one station acknowledges them,
// and the stations' verdict when none does (macula#12), as macula 15's pool
// does.

func refusing(reason string) func(string) (string, bool) {
	return func(string) (string, bool) { return reason, false }
}

// twoStations is a provider's pool linked to two stations, both up.
func twoStations(t *testing.T, name string) (*Pool, *teststation.Station, *teststation.Station, teststation.Realm) {
	t.Helper()
	a := teststation.Start(t, profile.PQPure, name+" a")
	b := teststation.Start(t, profile.PQPure, name+" b")
	teststation.ShareDHT(a, b)
	realm := teststation.NewRealm(t, profile.PQPure, name, org)
	providerID := nodeIDOf(t, name+" provider")
	realm.Admit(t, a, providerID)
	realm.Admit(t, b, providerID)
	p := connect(t, name+" provider", realm, a, b)
	eventually(t, "both links up", func() bool { return len(p.links()) == 2 })
	return p, a, b, realm
}

func TestServeHoldsWhenOneStationAccepts(t *testing.T) {
	p, a, b, realm := twoStations(t, "serve one refuses")
	a.Judge(refusing("too_many_providers"))
	if _, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v, want it served by the station that accepts", err)
	}
	if a.Advertised(realm.ID, procedure) || !b.Advertised(realm.ID, procedure) {
		t.Errorf("advertised at a %v and b %v, want b alone", a.Advertised(realm.ID, procedure), b.Advertised(realm.ID, procedure))
	}
}

func TestServeReturnsTheRefusalWhenEveryStationRefuses(t *testing.T) {
	p, a, b, realm := twoStations(t, "serve all refuse")
	a.Judge(refusing("advertiser_quota"))
	b.Judge(refusing("advertiser_quota"))
	served, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo})
	var refused *stationlink.RefusedError
	if !errors.As(err, &refused) || refused.Reason != "advertiser_quota" || served != nil {
		t.Fatalf("Serve: %v, %v; want the stations' refusal", served, err)
	}
	a.Judge(nil)
	if _, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Errorf("Serve once a station accepts: %v", err)
	}
}

func TestSubscribeReturnsTheRefusalWhenEveryStationRefuses(t *testing.T) {
	p, a, b, realm := twoStations(t, "subscribe all refuse")
	a.Judge(refusing("not_authorized"))
	b.Judge(refusing("too_many_realms"))
	sub, err := p.Subscribe(realm.ID, topic)
	var refused *stationlink.RefusedError
	if !errors.As(err, &refused) || refused.Kind != "subscribe" || refused.Name != topic || sub != nil {
		t.Fatalf("Subscribe: %v, %v; want a station's refusal", sub, err)
	}
	b.Judge(nil)
	if _, err := p.Subscribe(realm.ID, topic); err != nil {
		t.Fatalf("Subscribe once a station accepts: %v", err)
	}
	if a.Subscribed(p.NodeID(), realm.ID, topic) || !b.Subscribed(p.NodeID(), realm.ID, topic) {
		t.Errorf("subscribed at a %v and b %v, want b alone",
			a.Subscribed(p.NodeID(), realm.ID, topic), b.Subscribed(p.NodeID(), realm.ID, topic))
	}
}

// A station that does not answer holds up neither Serve nor Subscribe while
// another accepts: the pool returns on the first acceptance.
func TestASilentStationDoesNotHoldUpTheFirstAcceptance(t *testing.T) {
	p, a, b, realm := twoStations(t, "silent first")
	a.Judge(func(string) (string, bool) { return "", true })
	start := time.Now()
	if _, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if _, err := p.Subscribe(realm.ID, topic); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Errorf("Serve and Subscribe took %v with one station accepting", took)
	}
	if !b.Advertised(realm.ID, procedure) || !b.Subscribed(p.NodeID(), realm.ID, topic) {
		t.Error("the accepting station holds neither")
	}
}
