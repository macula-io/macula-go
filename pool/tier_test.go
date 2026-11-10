package pool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// tiers is a public station, a fallback station and the realm they both carry.
func tiers(t *testing.T) (*teststation.Station, *teststation.Station, teststation.Realm) {
	t.Helper()
	return teststation.Start(t, profile.PQPure, "tier public"),
		teststation.Start(t, profile.PQPure, "tier fallback"),
		teststation.NewRealm(t, profile.PQPure, "station tiers", org)
}

func seedsOf(stations []*teststation.Station) []Seed {
	seeds := make([]Seed, len(stations))
	for i, s := range stations {
		seeds[i] = seedOf(s)
	}
	return seeds
}

// connectTiered is a pool of node name on the two lists, closed when the test
// ends, with macula's defaults for everything but the tiers.
func connectTiered(t *testing.T, name string, realm teststation.Realm, public, fallback []*teststation.Station) *Pool {
	t.Helper()
	return connectTieredWith(t, name, realm, public, fallback, func(*Opts) {})
}

// connectTieredWith is a pool of node name on the two lists, shaped by shape,
// closed when the test ends.
func connectTieredWith(t *testing.T, name string, realm teststation.Realm, public, fallback []*teststation.Station,
	shape func(*Opts)) *Pool {
	t.Helper()
	opts := Opts{IdentityKey: teststation.Key(t, profile.PQPure, name),
		RealmTrust: map[[32]byte][]byte{realm.ID: realm.RealmKey()}, RespawnDelay: 100 * time.Millisecond,
		FallbackSeeds: seedsOf(fallback)}
	shape(&opts)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := Connect(ctx, seedsOf(public), opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// listenerOn is a pool linked only to s, subscribed to topic.
func listenerOn(t *testing.T, name string, realm teststation.Realm, s *teststation.Station) *Subscription {
	t.Helper()
	p := connect(t, name, realm, s)
	sub, err := p.Subscribe(realm.ID, topic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	eventually(t, "subscribed at "+name, func() bool { return s.Subscribed(p.NodeID(), realm.ID, topic) })
	return sub
}

func upCount(p *Pool) int {
	up := 0
	for _, l := range p.Status() {
		if l.Up {
			up++
		}
	}
	return up
}

// An originating publication goes to the active tier only: while a public link
// is up the fallback station carries nothing, though both are linked.
func TestAPublishReachesOnlyTheActiveTiersLinks(t *testing.T) {
	public, fallback, realm := tiers(t)
	publicSub := listenerOn(t, "public side", realm, public)
	fallbackSub := listenerOn(t, "fallback side", realm, fallback)
	p := connectTiered(t, "tier publisher", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	if got := p.ActiveTier(); got != TierPublic {
		t.Fatalf("both tiers up: the active tier is %v, want TierPublic", got)
	}
	say(t, p, realm, "on the public tier")
	if got := delivered(publicSub, 2*time.Second); len(got) != 1 {
		t.Errorf("%d deliveries on the public side, want 1", len(got))
	}
	if got := delivered(fallbackSub, 300*time.Millisecond); len(got) != 0 {
		t.Errorf("%d deliveries carried by the fallback station, want 0", len(got))
	}
}

// When no public station is up the pool reaches the fallback tier: Connect
// itself comes up on it, and the publication reaches the fallback link.
func TestAPublishOnTheFallbackReachesTheFallbackLink(t *testing.T) {
	public, fallback, realm := tiers(t)
	fallbackSub := listenerOn(t, "fallback side", realm, fallback)
	public.Stop()
	p := connectTiered(t, "fallback publisher", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	if got := p.ActiveTier(); got != TierFallback {
		t.Fatalf("the active tier is %v, want TierFallback", got)
	}
	say(t, p, realm, "on the fallback tier")
	if got := delivered(fallbackSub, 2*time.Second); len(got) != 1 {
		t.Errorf("%d deliveries on the fallback side, want 1", len(got))
	}
}

// The pool reports the tier it is on: public the moment a public link is up,
// fallback once none is, and public still for a pool that has no fallback list
// at all, so a pool with every link down fails as it did before tiers.
func TestTheStatusNamesTheTierThePoolIsOn(t *testing.T) {
	public, fallback, realm := tiers(t)
	p := connectTiered(t, "tier status", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	if got := p.ActiveTier(); got != TierPublic {
		t.Fatalf("both tiers up: the active tier is %v, want TierPublic", got)
	}
	public.Stop()
	eventually(t, "the pool on the fallback tier", func() bool { return p.ActiveTier() == TierFallback })
	solo := teststation.Start(t, profile.PQPure, "tier solo")
	only := connect(t, "no fallback tier", realm, solo)
	solo.Stop()
	eventually(t, "every link down", func() bool { return upCount(only) == 0 })
	if got := only.ActiveTier(); got != TierPublic {
		t.Errorf("a pool with no fallback list is on %v with every link down, want TierPublic", got)
	}
}

// Every link the pool holds names the tier its station was named in.
func TestEveryLinkNamesItsConfiguredTier(t *testing.T) {
	public, fallback, realm := tiers(t)
	p := connectTiered(t, "named tiers", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	want := map[[32]byte]Tier{public.NodeID: TierPublic, fallback.NodeID: TierFallback}
	statuses := p.Status()
	if len(statuses) != len(want) {
		t.Fatalf("%d links, want %d", len(statuses), len(want))
	}
	for _, l := range statuses {
		wantTier, named := want[l.Station]
		if !named {
			t.Errorf("link %x is not a station the pool was given", l.Station[:4])
			continue
		}
		if l.Tier != wantTier {
			t.Errorf("link %x is on the %v tier, want %v", l.Station[:4], l.Tier, wantTier)
		}
	}
}

// One station with two roles has no defined behaviour, so the pool refuses to
// start: the caller would otherwise be making a silent choice about where
// their traffic goes.
func TestAStationInBothTiersRefusesTheConnect(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "both tiers")
	opts := Opts{IdentityKey: teststation.Key(t, profile.PQPure, "both tiers client"), FallbackSeeds: []Seed{seedOf(s)}}
	if _, err := Connect(t.Context(), []Seed{seedOf(s)}, opts); !errors.Is(err, ErrStationInBothTiers) {
		t.Errorf("the same seed in both lists: %v, want ErrStationInBothTiers", err)
	}
	other := seedOf(s)
	other.Port++
	opts.FallbackSeeds = []Seed{other}
	if _, err := Connect(t.Context(), []Seed{seedOf(s)}, opts); !errors.Is(err, ErrStationInBothTiers) {
		t.Errorf("one node_id at two addresses, want ErrStationInBothTiers: %v", err)
	}
	stranger := seedOf(s)
	stranger.NodeID = nodeIDOf(t, "both tiers stranger")
	opts.FallbackSeeds = []Seed{stranger}
	if _, err := Connect(t.Context(), []Seed{seedOf(s)}, opts); !errors.Is(err, ErrStationInBothTiers) {
		t.Errorf("one address under two node_ids, want ErrStationInBothTiers: %v", err)
	}
}

// A station a pool dials for a call is public: the pool was handed its route
// by an advertisement, not by a caller keeping a LAN tier.
func TestAStationDialledForACallIsPublic(t *testing.T) {
	serving := teststation.Start(t, profile.PQPure, "tier serving")
	public, fallback, realm := tiers(t)
	teststation.ShareDHT(serving, public)
	realm.Admit(t, serving, nodeIDOf(t, "tier provider"))
	provider := connect(t, "tier provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connectTiered(t, "tier caller", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	if _, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello")}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	eventually(t, "the serving station dialled", func() bool { return serving.Connected(caller.NodeID()) })
	found := false
	for _, l := range caller.Status() {
		if l.Station == serving.NodeID {
			found = true
			if !l.Direct || l.Tier != TierPublic {
				t.Errorf("the station dialled for a call is %+v, want a direct link on the public tier", l)
			}
		}
	}
	if !found {
		t.Fatal("the station dialled for a call is not in the pool's status")
	}
}

// Every link event names the tier its station was named in, so a binding can
// say "offline: on the LAN fallback" from the event that took the link down, not
// only from a status read afterwards (macula#201 §6).
func TestALinkEventNamesTheTier(t *testing.T) {
	public, fallback, realm := tiers(t)
	events := make(chan LinkEvent, 32)
	p := connectTieredWith(t, "tier events", realm, []*teststation.Station{public},
		[]*teststation.Station{fallback}, func(o *Opts) {
			o.OnLinkEvent = func(e LinkEvent) { events <- e }
		})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	want := map[[32]byte]Tier{public.NodeID: TierPublic, fallback.NodeID: TierFallback}
	seen := map[[32]byte]Tier{}
	deadline := time.After(5 * time.Second)
	for len(seen) < len(want) {
		select {
		case e := <-events:
			if e.Up {
				seen[e.Station] = e.Tier
			}
		case <-deadline:
			t.Fatalf("%d stations reported a link event, want %d", len(seen), len(want))
		}
	}
	for station, tier := range seen {
		if tier != want[station] {
			t.Errorf("the link event for %x names tier %v, want %v", station[:4], tier, want[station])
		}
	}
}

// measuredRTT makes the pool read every link's round trip from rtts until the
// test ends: the RTT a real handshake settles on is not something a test can
// choose.
func measuredRTT(t *testing.T, rtts map[[32]byte]time.Duration) {
	t.Helper()
	restore := rttOf
	rttOf = func(l *stationlink.Link) (time.Duration, bool) {
		rtt, measured := rtts[l.StationNodeID()]
		return rtt, measured
	}
	t.Cleanup(func() { rttOf = restore })
}

// The lowest measured round trip goes first among the active tier's links, so
// with one copy to make it is the fast station that carries it, whichever order
// the seeds were given in.
func TestTheLowestMeasuredRoundTripIsPublishedToFirst(t *testing.T) {
	slow := teststation.Start(t, profile.PQPure, "rtt slow")
	fast := teststation.Start(t, profile.PQPure, "rtt fast")
	realm := teststation.NewRealm(t, profile.PQPure, "rtt order", org)
	slowSub := listenerOn(t, "slow side", realm, slow)
	fastSub := listenerOn(t, "fast side", realm, fast)
	p := connectWith(t, "rtt publisher", realm, func(o *Opts) { o.ReplicationFactor = 1 }, slow, fast)
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	measuredRTT(t, map[[32]byte]time.Duration{fast.NodeID: 5 * time.Millisecond, slow.NodeID: 90 * time.Millisecond})
	say(t, p, realm, "to the lowest round trip")
	if got := delivered(fastSub, 2*time.Second); len(got) != 1 {
		t.Errorf("%d deliveries at the fast station, want 1", len(got))
	}
	if got := delivered(slowSub, 300*time.Millisecond); len(got) != 0 {
		t.Errorf("%d deliveries at the slow station, want 0: the lowest round trip was not first", len(got))
	}
	// A link with no measurement yet sorts after every measured one, so the
	// measured station carries a publication even when it is the slower seed.
	measuredRTT(t, map[[32]byte]time.Duration{slow.NodeID: 90 * time.Millisecond})
	say(t, p, realm, "past the unmeasured link")
	if got := delivered(slowSub, 2*time.Second); len(got) != 1 {
		t.Errorf("%d deliveries at the measured station, want 1: an unmeasured link went first", len(got))
	}
}
