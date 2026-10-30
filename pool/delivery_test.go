package pool

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// The last link to end owes one Interrupted, from the latest time a link that
// left last heard from its station, and the first to carry the subscription
// again owes one Gap; neither is owed while another link still carries it.
func TestCoverageOwesOneInterruptedAndOneGap(t *testing.T) {
	c := newCoverage[int]()
	if _, owed := c.covers(1, 100); owed {
		t.Error("a Gap owed at the first subscribe")
	}
	c.covers(2, 110)
	if _, owed := c.ended(1, 500, "liveness_lost"); owed {
		t.Error("an Interrupted owed while link 2 still carries it")
	}
	interrupted, owed := c.ended(2, 400, "closed_by_station")
	if !owed || interrupted.Kind != KindInterrupted || interrupted.FromMs != 500 || interrupted.Reason != "closed_by_station" {
		t.Fatalf("ended the last link: %+v %v, want Interrupted from 500 (the latest heard) for closed_by_station", interrupted, owed)
	}
	gap, owed := c.covers(3, 900)
	if !owed || gap.Kind != KindGap || gap.FromMs != 500 || gap.ToMs != 900 || gap.Reason != "closed_by_station" {
		t.Fatalf("covered again: %+v %v, want a Gap from 500 to 900", gap, owed)
	}
	if _, owed := c.covers(4, 950); owed {
		t.Error("a second Gap owed by a second link")
	}
}

// A link that ends before a station accepted the subscription on it never
// carried it: it neither interrupts nor fills the set.
func TestCoverageIgnoresALinkThatNeverCarriedIt(t *testing.T) {
	c := newCoverage[int]()
	if _, owed := c.ended(1, 100, "liveness_lost"); owed {
		t.Error("an Interrupted owed by a link that never carried the subscription")
	}
	c.covers(2, 200)
	c.ended(2, 300, "liveness_lost")
	if _, owed := c.ended(3, 400, "closed"); owed {
		t.Error("a second Interrupted owed by a link that ended before its ack")
	}
	gap, _ := c.covers(4, 500)
	if gap.FromMs != 300 || gap.Reason != "liveness_lost" {
		t.Errorf("the Gap %+v, want it from the link that carried the subscription", gap)
	}
}

// After a Gap the latest heard starts again: the next interruption is from
// the links that ended since.
func TestCoverageStartsHeardAgainAfterAGap(t *testing.T) {
	c := newCoverage[int]()
	c.covers(1, 100)
	c.ended(1, 900, "liveness_lost")
	c.covers(2, 1000)
	interrupted, _ := c.ended(2, 800, "goodbye")
	if interrupted.FromMs != 800 {
		t.Errorf("the second Interrupted is from %d, want 800", interrupted.FromMs)
	}
}

// listening is a listener's pool on stations, subscribed to topic, and a
// publisher's pool on publishers.
func listening(t *testing.T, name string, stations, publishers []*teststation.Station) (*Pool, *Subscription, *Pool, teststation.Realm) {
	t.Helper()
	realm := teststation.NewRealm(t, profile.PQPure, name, org)
	listener := connect(t, name+" listener", realm, stations...)
	eventually(t, "every listener link up", func() bool { return len(listener.links()) == len(stations) })
	publisher := connect(t, name+" publisher", realm, publishers...)
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
	return listener, sub, publisher, realm
}

func say(t *testing.T, p *Pool, realm teststation.Realm, text string) {
	t.Helper()
	if err := p.Publish(stationlink.Publication{Realm: realm.ID, Topic: topic, Payload: cbor.Text(text)}); err != nil {
		t.Fatalf("Publish %q: %v", text, err)
	}
}

// delivered is what sub delivers within d, or until it closes.
func delivered(sub *Subscription, d time.Duration) []Delivery {
	var got []Delivery
	timeout := time.After(d)
	for {
		select {
		case item, open := <-sub.Events():
			if !open {
				return got
			}
			got = append(got, item)
		case <-timeout:
			return got
		}
	}
}

// awaited is the first delivery of kind within d, and what sub delivered
// before it.
func awaited(t *testing.T, sub *Subscription, kind DeliveryKind, d time.Duration) (Delivery, []Delivery) {
	t.Helper()
	var before []Delivery
	timeout := time.After(d)
	for {
		select {
		case item, open := <-sub.Events():
			if !open {
				t.Fatalf("the subscription closed before a %s, after %s", kind, shown(before))
			}
			if item.Kind == kind {
				return item, before
			}
			before = append(before, item)
		case <-timeout:
			t.Fatalf("no %s within %s, after %s", kind, d, shown(before))
		}
	}
}

// shown is deliveries as kinds, an event by its text.
func shown(deliveries []Delivery) string {
	parts := make([]string, len(deliveries))
	for i, d := range deliveries {
		parts[i] = d.Kind.String()
		if d.Kind == KindEvent {
			text, _ := d.Event.Payload.AsText()
			parts[i] = fmt.Sprintf("event %q", text)
		}
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// An outage longer than liveness ends the only link: the subscription is
// interrupted from when that link last heard from its station, before the
// outage, and once the station accepts it on the next link a Gap follows,
// before any event that link carries. What was published in the outage is
// lost, which is what the notices say.
func TestAnOutagePastLivenessDeliversAnInterruptedThenAGap(t *testing.T) {
	t.Parallel()
	station := teststation.Start(t, profile.PQPure, "outage")
	listener, sub, publisher, realm := listening(t, "outage", []*teststation.Station{station}, []*teststation.Station{station})
	silenced := time.Now()
	station.Silence(listener.NodeID(), 90*time.Second)
	say(t, publisher, realm, "during")
	interrupted, before := awaited(t, sub, KindInterrupted, 100*time.Second)
	interruptedAt := uint64(time.Now().UnixMilli())
	if len(before) != 0 {
		t.Errorf("before the Interrupted: %s, want nothing", shown(before))
	}
	from := time.UnixMilli(int64(interrupted.FromMs))
	if interrupted.Reason != "liveness_lost" || from.After(silenced.Add(time.Second)) || from.Before(silenced.Add(-35*time.Second)) {
		t.Errorf("Interrupted from %s for %q; want liveness_lost, from at most 1 s after the outage began at %s",
			from, interrupted.Reason, silenced)
	}
	// Events published from now on reach the next link as soon as its
	// station holds the subscription, some of them before its ack.
	stop := ticking(publisher, realm, "after")
	gap, between := awaited(t, sub, KindGap, 15*time.Second)
	after := delivered(sub, time.Second)
	stop()
	if len(between) != 0 {
		t.Errorf("between the Interrupted and the Gap: %s, want nothing", shown(between))
	}
	if gap.FromMs != interrupted.FromMs || gap.ToMs < interruptedAt || gap.Reason != interrupted.Reason {
		t.Errorf("the Gap %+v; want it from the Interrupted's %d to after %d, for %q", gap, interrupted.FromMs,
			interruptedAt, interrupted.Reason)
	}
	for _, d := range after {
		if text, _ := d.Event.Payload.AsText(); d.Kind != KindEvent || !strings.HasPrefix(text, "after") {
			t.Fatalf("after the Gap: %s, want the events published after the outage alone", shown(after))
		}
	}
	if len(after) == 0 {
		t.Error("no event after the Gap")
	}
}

// ticking publishes "prefix n" every 20 ms until the returned stop is called.
func ticking(p *Pool, realm teststation.Realm, prefix string) (stop func()) {
	done, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			case <-time.After(20 * time.Millisecond):
			}
			_ = p.Publish(stationlink.Publication{Realm: realm.ID, Topic: topic, Payload: cbor.Text(fmt.Sprintf("%s %d", prefix, i))})
		}
	}()
	return func() {
		close(done)
		<-stopped
	}
}

// An outage the link survives loses nothing and says nothing.
func TestAShortOutageTheLinkSurvivesDeliversNoNotice(t *testing.T) {
	t.Parallel()
	station := teststation.Start(t, profile.PQPure, "short outage")
	listener, sub, publisher, realm := listening(t, "short outage", []*teststation.Station{station}, []*teststation.Station{station})
	link := listener.links()[0]
	station.Silence(listener.NodeID(), 10*time.Second)
	got := delivered(sub, 45*time.Second)
	if len(got) != 0 {
		t.Errorf("across a 10 s outage and the probe after it: %s, want nothing", shown(got))
	}
	if links := listener.links(); len(links) != 1 || links[0] != link {
		t.Fatal("the link did not survive the outage")
	}
	say(t, publisher, realm, "after")
	if got := delivered(sub, 2*time.Second); len(got) != 1 || got[0].Kind != KindEvent {
		t.Errorf("after the outage: %s, want the event", shown(got))
	}
}

// With two links, one ending is no gap: the other carries every event.
func TestOneOfTwoLinksEndingDeliversNoNotice(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "one of two a")
	b := teststation.Start(t, profile.PQPure, "one of two b")
	listener, sub, publisher, realm := listening(t, "one of two", []*teststation.Station{a, b}, []*teststation.Station{a})
	b.Stop()
	eventually(t, "the link to b ended", func() bool { return len(listener.links()) == 1 })
	say(t, publisher, realm, "still")
	if got := delivered(sub, 2*time.Second); len(got) != 1 || got[0].Kind != KindEvent {
		t.Errorf("after one link ended: %s, want the event alone", shown(got))
	}
}

// With two links that both end and one that returns, the subscription is
// interrupted once and given one Gap; the other station staying down adds
// nothing.
func TestBothLinksEndingAndOneReturningDeliversOneOfEach(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "both end a")
	b := teststation.Start(t, profile.PQPure, "both end b")
	listener, sub, _, _ := listening(t, "both end", []*teststation.Station{a, b}, []*teststation.Station{a})
	b.Stop()
	eventually(t, "the link to b ended", func() bool { return len(listener.links()) == 1 })
	a.Drop(listener.NodeID())
	interrupted, before := awaited(t, sub, KindInterrupted, 10*time.Second)
	if len(before) != 0 || interrupted.Reason != "closed_by_station" {
		t.Errorf("before it %s, then Interrupted for %q; want nothing, then closed_by_station", shown(before), interrupted.Reason)
	}
	if gap, before := awaited(t, sub, KindGap, 10*time.Second); len(before) != 0 || gap.FromMs != interrupted.FromMs {
		t.Errorf("before the Gap %s, the Gap %+v; want nothing, from the Interrupted's %d", shown(before), gap, interrupted.FromMs)
	}
	if got := delivered(sub, 3*time.Second); len(got) != 0 {
		t.Errorf("while b stays down: %s, want nothing", shown(got))
	}
}

// A subscription the station refuses on the next link stays interrupted: no
// Gap while the refusal stands.
func TestARefusedResubscribeDeliversNoGap(t *testing.T) {
	station := teststation.Start(t, profile.PQPure, "refused again")
	listener, sub, _, _ := listening(t, "refused again", []*teststation.Station{station}, []*teststation.Station{station})
	station.Judge(refusing("not_authorized"))
	station.Drop(listener.NodeID())
	awaited(t, sub, KindInterrupted, 10*time.Second)
	eventually(t, "the listener redialed", func() bool { return len(listener.links()) == 1 })
	if got := delivered(sub, 3*time.Second); len(got) != 0 {
		t.Errorf("while the station refuses: %s, want nothing", shown(got))
	}
}

// A subscription ended while interrupted delivers nothing more.
func TestUnsubscribingWhileInterruptedDeliversNothingMore(t *testing.T) {
	station := teststation.Start(t, profile.PQPure, "unsubscribed")
	listener, sub, _, _ := listening(t, "unsubscribed", []*teststation.Station{station}, []*teststation.Station{station})
	station.Judge(refusing("not_authorized"))
	station.Drop(listener.NodeID())
	awaited(t, sub, KindInterrupted, 10*time.Second)
	if err := sub.Unsubscribe(); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	station.Judge(nil)
	station.Drop(listener.NodeID())
	eventually(t, "the listener redialed", func() bool { return len(listener.links()) == 1 })
	if got := delivered(sub, 2*time.Second); len(got) != 0 {
		t.Errorf("after Unsubscribe: %s, want the subscription closed", shown(got))
	}
}
