package pool

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// waitingLen is how many publications a pool holds for a link to be up.
func waitingLen(p *Pool) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.waiting)
}

// subscribedListener is a pool on stations, subscribed to the test's topic, and
// its subscription.
func subscribedListener(t *testing.T, name string, realm teststation.Realm, stations ...*teststation.Station) (*Pool, *Subscription) {
	t.Helper()
	listener := connect(t, name, realm, stations...)
	eventually(t, "every listener link up", func() bool { return len(listener.links()) == len(stations) })
	sub, err := listener.Subscribe(realm.ID, topic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	eventually(t, "subscribed at every station", func() bool {
		for _, s := range stations {
			if !s.Subscribed(listener.NodeID(), realm.ID, topic) {
				return false
			}
		}
		return true
	})
	return listener, sub
}

// eventuallyWithin is eventually with a deadline of its own, for a wait that
// must be short to mean anything.
func eventuallyWithin(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("not within %s: %s", d, what)
}

// firstDelivery is the subscription's next delivery within d, or a failure: a
// test that expects exactly one does not wait out a full window to hear nothing.
func firstDelivery(t *testing.T, sub *Subscription, d time.Duration) Delivery {
	t.Helper()
	select {
	case item, open := <-sub.Events():
		if !open {
			t.Fatal("the subscription closed before a delivery")
		}
		return item
	case <-time.After(d):
		t.Fatalf("no delivery within %s", d)
	}
	return Delivery{}
}

// signedFor is a publication signed on the pool's own key and seq, as Publish
// signs one, so a test can hand the same one to the pool twice.
func signedFor(t *testing.T, p *Pool, realm teststation.Realm, text string, ttlMs *uint64) stationlink.SignedPublication {
	t.Helper()
	signed, err := stationlink.SignPublication(p.key, p.shared.PublicationSeq, stationlink.Publication{
		Realm: realm.ID, Topic: topic, Payload: cbor.Text(text), TTLMs: ttlMs})
	if err != nil {
		t.Fatalf("SignPublication: %v", err)
	}
	return signed
}

// A publication a link held goes out on another link when that link ends, and
// the subscriber hears it once.
func TestAHeldPublicationGoesOutOnAnotherLinkWhenItsLinkEnds(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "another link a")
	b := teststation.Start(t, profile.PQPure, "another link b")
	b.Refuse(time.Minute)
	realm := teststation.NewRealm(t, profile.PQPure, "another link", org)
	publisher := connect(t, "another link publisher", realm, a, b)
	eventually(t, "one link up", func() bool { return len(publisher.links()) == 1 })
	say(t, publisher, realm, "held on a")
	b.Allow()
	eventually(t, "both links up", func() bool { return len(publisher.links()) == 2 })

	_, sub := subscribedListener(t, "another link listener", realm, b)
	a.Drop(publisher.NodeID())
	got := firstDelivery(t, sub, 5*time.Second)
	if text, _ := got.Event.Payload.AsText(); got.Kind != KindEvent || text != "held on a" {
		t.Errorf("after the link holding it ended: %s, want the publication once", shown([]Delivery{got}))
	}
	if again := delivered(sub, 300*time.Millisecond); len(again) != 0 {
		t.Errorf("delivered again: %s, want it once", shown(again))
	}
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent, want none", sent)
	}
}

// With no link up what a link held waits, and the link that comes up next
// carries it.
func TestAPublicationWithNoLinkUpWaitsForTheNextOne(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "waiting a")
	listener, sub, publisher, realm := listening(t, "waiting", []*teststation.Station{a}, []*teststation.Station{a})
	_ = listener
	say(t, publisher, realm, "waits for a link")
	if got := firstDelivery(t, sub, 3*time.Second); got.Kind != KindEvent {
		t.Fatalf("before the outage: %s, want the publication", shown([]Delivery{got}))
	}
	a.Drop(publisher.NodeID())
	eventually(t, "the publication waits", func() bool { return waitingLen(publisher) == 1 })
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent while one waits, want none", sent)
	}
	eventually(t, "the next link carries it", func() bool { return waitingLen(publisher) == 0 })
	if got := delivered(sub, 2*time.Second); len(got) != 0 {
		t.Errorf("delivered again after the re-send: %s, want it once", shown(got))
	}
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent after it went out, want none", sent)
	}
}

// What waits goes out before a publication a caller signs next: best effort,
// within that caller's own call.
func TestWhatWaitsGoesOutBeforeANewerPublication(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "before a newer a")
	_, sub, publisher, realm := listening(t, "before a newer", []*teststation.Station{a}, []*teststation.Station{a})
	publisher.keep(signedFor(t, publisher, realm, "older", nil))
	say(t, publisher, realm, "newer")
	first, _ := firstDelivery(t, sub, 3*time.Second).Event.Payload.AsText()
	second, _ := firstDelivery(t, sub, 3*time.Second).Event.Payload.AsText()
	if first != "older" || second != "newer" {
		t.Errorf("delivered %q then %q, want older then newer", first, second)
	}
	if n := waitingLen(publisher); n != 0 {
		t.Errorf("%d publications still wait after the publish drained them, want none", n)
	}
}

// The window between recording a hold and writing the frame: the link ends
// there, the pool's own hand-over takes the set, and the write then fails
// having written nothing. The publication is carried by the take — the caller
// is told nothing, and the next link carries it exactly once.
func TestAPublicationWhoseLinkEndsBetweenTheHoldAndItsWriteIsNotLost(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "held window a")
	_, sub, publisher, realm := listening(t, "held window", []*teststation.Station{a}, []*teststation.Station{a})
	restore := stationlink.AfterHeld
	t.Cleanup(func() { stationlink.AfterHeld = restore })
	var once sync.Once
	stationlink.AfterHeld = func() {
		once.Do(func() {
			a.Drop(publisher.NodeID())
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				if waitingLen(publisher) == 1 {
					return
				}
				time.Sleep(time.Millisecond)
			}
			t.Errorf("the hand-over never took the held publication")
		})
	}
	if err := publisher.Publish(stationlink.Publication{Realm: realm.ID, Topic: topic, Payload: cbor.Text("in the window")}); err != nil {
		t.Fatalf("Publish: %v, want nil: the hand-over carries it", err)
	}
	stationlink.AfterHeld = restore
	if n := waitingLen(publisher); n != 1 {
		t.Fatalf("%d publications wait after the write in that window, want the one held", n)
	}
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent, want none", sent)
	}
	eventually(t, "the next link carries it", func() bool { return waitingLen(publisher) == 0 })
	got := firstDelivery(t, sub, 3*time.Second)
	if text, _ := got.Event.Payload.AsText(); got.Kind != KindEvent || text != "in the window" {
		t.Fatalf("delivered %s, want the publication once", shown([]Delivery{got}))
	}
	if again := delivered(sub, 300*time.Millisecond); len(again) != 0 {
		t.Errorf("delivered again: %s, want it once", shown(again))
	}
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent after it went out, want none", sent)
	}
}

// A publication subscribers would refuse by the time a re-send could reach them
// is counted unsent, not sent.
func TestAPublicationPastItsResendDeadlineIsCountedUnsent(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "past the deadline a")
	_, _, publisher, realm := listening(t, "past the deadline", []*teststation.Station{a}, []*teststation.Station{a})
	ttl := uint64(0)
	publisher.keep(signedFor(t, publisher, realm, "too old", &ttl))
	time.Sleep(2 * time.Millisecond) // past the moment a subscriber would accept it
	publisher.drainWaiting()
	if sent := publisher.UnsentPublications(); sent != 1 {
		t.Errorf("%d publications counted unsent, want the expired one", sent)
	}
	if n := waitingLen(publisher); n != 0 {
		t.Errorf("%d publications still wait, want none: the expired one was counted", n)
	}
}

// The waiting queue is bounded by entries and by bytes, and counts what it
// cannot keep.
func TestTheWaitingQueueCountsWhatItCannotKeep(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "queue bounds a")
	_, _, publisher, realm := listening(t, "queue bounds", []*teststation.Station{a}, []*teststation.Station{a})
	for i := range maxWaiting + 1 {
		publisher.keep(signedFor(t, publisher, realm, fmt.Sprintf("small %d", i), nil))
	}
	if sent := publisher.UnsentPublications(); sent != 1 {
		t.Errorf("%d publications counted unsent over the entry cap, want 1", sent)
	}
	if n := waitingLen(publisher); n != maxWaiting {
		t.Errorf("%d publications wait, want %d", n, maxWaiting)
	}

	// The byte cap, on a pool of its own: entries for all of them, bytes for
	// two. Each is a third of the cap and change, so three cross it and each
	// fits a frame.
	b := teststation.Start(t, profile.PQPure, "queue bytes b")
	_, _, byBytes, realmOf := listening(t, "queue bytes", []*teststation.Station{b}, []*teststation.Station{b})
	payload := cbor.Bytes(make([]byte, maxWaitingBytes/3+64*1024))
	for i := range 3 {
		big, err := stationlink.SignPublication(byBytes.key, byBytes.shared.PublicationSeq, stationlink.Publication{
			Realm: realmOf.ID, Topic: topic, Payload: payload})
		if err != nil {
			t.Fatalf("SignPublication %d: %v", i, err)
		}
		byBytes.keep(big)
	}
	if sent := byBytes.UnsentPublications(); sent != 1 {
		t.Errorf("%d publications counted unsent over the byte cap, want 1", sent)
	}
	if n := waitingLen(byBytes); n != 2 {
		t.Errorf("%d publications wait by bytes, want 2", n)
	}
}

// A close counts every publication still waiting exactly once, after the
// members have stopped: what an ended link still held is counted by the
// hand-over that finds the pool closed, and what waits is counted here.
func TestClosingCountsEveryHeldAndWaitingPublicationOnce(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "closing a")
	_, sub, publisher, realm := listening(t, "closing", []*teststation.Station{a}, []*teststation.Station{a})
	say(t, publisher, realm, "held on the link")
	if got := firstDelivery(t, sub, 3*time.Second); got.Kind != KindEvent {
		t.Fatalf("delivered %s, want the publication", shown([]Delivery{got}))
	}
	// The station takes nothing more, so what the link held waits and nothing
	// drains it.
	a.Refuse(time.Minute)
	a.Drop(publisher.NodeID())
	eventually(t, "the held publication waits", func() bool { return waitingLen(publisher) == 1 })
	publisher.keep(signedFor(t, publisher, realm, "waits with it", nil))
	if err := publisher.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sent := publisher.UnsentPublications(); sent != 2 {
		t.Errorf("%d publications counted unsent at close, want the held one and the one kept with it", sent)
	}
}

// A re-sent copy of a publication the subscriber already heard is delivered
// once, whatever links carried it.
func TestAReSentPublicationIsDeliveredOnce(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "re-sent once a")
	listener, sub, publisher, realm := listening(t, "re-sent once", []*teststation.Station{a}, []*teststation.Station{a})
	once := signedFor(t, publisher, realm, "the same publication", nil)
	if !publisher.send(once) {
		t.Fatal("the first copy was not carried")
	}
	if got := firstDelivery(t, sub, 3*time.Second); got.Kind != KindEvent {
		t.Fatalf("delivered %s, want the publication once", shown([]Delivery{got}))
	}
	if !publisher.send(once) {
		t.Fatal("the second copy was not carried: the tuple cannot tell it from the first")
	}
	eventually(t, "the second copy reached the listener and was dropped as a duplicate", func() bool {
		for _, link := range listener.links() {
			if link.Unrouted()["event_duplicate"] > 0 {
				return true
			}
		}
		return false
	})
	if got := delivered(sub, 500*time.Millisecond); len(got) != 0 {
		t.Errorf("delivered the copy again: %s", shown(got))
	}
}

// A re-send selects like a publish: while the public tier has a link up it
// never writes into the fallback, however much faster the fallback is.
func TestAResendGoesWhereAPublishWould(t *testing.T) {
	t.Parallel()
	public := teststation.Start(t, profile.PQPure, "resend tier public")
	fallback := teststation.Start(t, profile.PQPure, "resend tier fallback")
	realm := teststation.NewRealm(t, profile.PQPure, "resend tier", org)
	restore := rttOf
	rttOf = func(l *stationlink.Link) (time.Duration, bool) {
		if l.StationNodeID() == fallback.NodeID {
			return time.Millisecond, true
		}
		return time.Second, true
	}
	t.Cleanup(func() { rttOf = restore })
	publisher := connectWith(t, "resend tier publisher", realm, func(o *Opts) {
		o.FallbackSeeds = []Seed{seedOf(fallback)}
	}, public)
	eventually(t, "both links up", func() bool { return len(publisher.links()) == 2 })
	_, publicSub := subscribedListener(t, "resend tier public listener", realm, public)
	_, fallbackSub := subscribedListener(t, "resend tier fallback listener", realm, fallback)
	publisher.resend([]stationlink.SignedPublication{signedFor(t, publisher, realm, "tier", nil)})
	if got := firstDelivery(t, publicSub, 3*time.Second); got.Kind != KindEvent {
		t.Fatalf("the public listener heard %s, want the publication once", shown([]Delivery{got}))
	}
	if got := delivered(fallbackSub, 500*time.Millisecond); len(got) != 0 {
		t.Errorf("the fallback listener heard %s while the public tier was up, want nothing", shown(got))
	}
}

// attempts is how many backoff retries a station's member has taken.
func attempts(p *Pool, station [32]byte) int {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	for _, m := range members {
		if m.target.ExpectedNodeID != station {
			continue
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.attempts
	}
	return -1
}

// A station slow to acknowledge a SUBSCRIBE delays neither the link nor the
// tier notice that follows it: the drain waits for the attach, and nothing else
// does.
func TestAnUnansweredSubscribeDoesNotDelayTheTierRearm(t *testing.T) {
	restore := randBelow
	randBelow = func(time.Duration) time.Duration { return 0 }
	t.Cleanup(func() { randBelow = restore })

	a := teststation.Start(t, profile.PQPure, "tier rearm a")
	b := teststation.Start(t, profile.PQPure, "tier rearm b")
	f := teststation.Start(t, profile.PQPure, "tier rearm fallback")
	a.Refuse(time.Hour)
	b.Refuse(time.Hour)
	realm := teststation.NewRealm(t, profile.PQPure, "tier rearm", org)
	p := connectWith(t, "tier rearm", realm, func(o *Opts) {
		o.FallbackSeeds = []Seed{seedOf(f)}
		o.Redial = Redial{Base: 20 * time.Millisecond, Factor: 2, Cap: time.Minute, SteadyUp: time.Minute}
		o.RespawnDelay = 20 * time.Millisecond
	}, a, b)
	eventually(t, "the fallback link is up", func() bool { return len(p.links()) == 1 })
	if _, err := p.Subscribe(realm.ID, topic); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	eventually(t, "a public station parked on its backoff", func() bool { return attempts(p, a.NodeID) >= 3 })

	release := b.HoldAcks()
	t.Cleanup(release)
	b.Allow()
	eventually(t, "b's link up", func() bool { return b.Connected(p.NodeID()) })
	eventuallyWithin(t, "the tier notice re-armed the parked station", 2*time.Second, func() bool {
		return attempts(p, a.NodeID) == 0
	})
}

// At the default ReplicationFactor a publication is written to two links, and
// each hand-over carries a copy of it: with no link left to take it, the pool
// queues it once and counts it once.
func TestAPublicationItsLinksBothEndedWaitsOnceAndIsCountedOnce(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "two copies a")
	b := teststation.Start(t, profile.PQPure, "two copies b")
	_, _, publisher, realm := listening(t, "two copies", []*teststation.Station{a, b}, []*teststation.Station{a, b})
	eventually(t, "both links up", func() bool { return len(publisher.links()) == 2 })
	once := signedFor(t, publisher, realm, "held by both links", nil)
	// No link is left to take it, and the station takes nothing more.
	a.Refuse(time.Minute)
	b.Refuse(time.Minute)
	a.Drop(publisher.NodeID())
	b.Drop(publisher.NodeID())
	eventually(t, "no link up", func() bool { return len(publisher.links()) == 0 })
	publisher.resend([]stationlink.SignedPublication{once, once}) // what both hand-overs carry
	if n := waitingLen(publisher); n != 1 {
		t.Fatalf("%d publications wait after both copies were handed over, want the one", n)
	}
	if err := publisher.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sent := publisher.UnsentPublications(); sent != 1 {
		t.Errorf("%d publications counted unsent at close, want the one", sent)
	}
}

// A copy handed over after the publication already went out on another link is
// neither queued again nor counted.
func TestACopyOfAPublicationThatWentOutIsNotCounted(t *testing.T) {
	t.Parallel()
	a := teststation.Start(t, profile.PQPure, "copy went out a")
	b := teststation.Start(t, profile.PQPure, "copy went out b")
	_, _, publisher, realm := listening(t, "copy went out", []*teststation.Station{a, b}, []*teststation.Station{a, b})
	eventually(t, "both links up", func() bool { return len(publisher.links()) == 2 })
	once := signedFor(t, publisher, realm, "carried on the other link", nil)
	publisher.resend([]stationlink.SignedPublication{once}) // a link takes it, as a hand-over's copy
	// The second link's copy arrives after the first went out, and with no link
	// left to take it.
	a.Refuse(time.Minute)
	b.Refuse(time.Minute)
	a.Drop(publisher.NodeID())
	b.Drop(publisher.NodeID())
	eventually(t, "no link up", func() bool { return len(publisher.links()) == 0 })
	publisher.resend([]stationlink.SignedPublication{once})
	if n := waitingLen(publisher); n != 0 {
		t.Errorf("%d publications wait after a copy of one that went out, want none", n)
	}
	if err := publisher.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if sent := publisher.UnsentPublications(); sent != 0 {
		t.Errorf("%d publications counted unsent, want none: a copy already went out", sent)
	}
}
