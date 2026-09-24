package stationlink

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// Links of one node share one admission: a copy of a CALL answered on one link
// gets the same stored reply on the other, and the handler runs once.
func TestLinksSharingAnAdmissionRunARequestOnce(t *testing.T) {
	admission := NewAdmission(DefaultAdmissionLimits())
	shared := func(share string) func(*Config) {
		return func(c *Config) { c.Admission, c.Share = admission, share }
	}
	var runs atomic.Int32
	counting := func(_ context.Context, r Request) (cbor.Value, error) {
		runs.Add(1)
		return r.Payload, nil
	}
	first, a, fixtureA := startServingWith(t, profile.PQPure, shared("a"))
	second, b, fixtureB := startServingWith(t, profile.PQPure, shared("b"))
	serveEcho(t, first, fixtureA, counting)
	serveEcho(t, second, fixtureB, counting)
	a.nextControl(t)
	b.nextControl(t)
	signed, _ := a.call(t, first.NodeID(), servedProcedure, cbor.Text("once"), time.Now().Add(5*time.Second))
	answered := cbor.Encode(a.nextOther(t))
	b.send(cbor.Encode(signed))
	if copied := cbor.Encode(b.nextOther(t)); !bytes.Equal(answered, copied) {
		t.Error("the other link's reply is not the stored one")
	}
	if n := runs.Load(); n != 1 {
		t.Errorf("the handler ran %d times", n)
	}
}

// A share holds at most its bound of pending entries, whichever callers they
// are from.
func TestAShareHoldsAtMostItsBound(t *testing.T) {
	limits := DefaultAdmissionLimits()
	limits.CallerQuota, limits.Share = 1, 1
	admission := NewAdmission(limits)
	link, s, fixture := startServingWith(t, profile.PQPure, func(c *Config) { c.Admission, c.Share = admission, "only" })
	serveEcho(t, link, fixture, func(ctx context.Context, r Request) (cbor.Value, error) {
		<-ctx.Done()
		return r.Payload, nil
	})
	s.nextControl(t)
	s.call(t, link.NodeID(), servedProcedure, cbor.Text("held"), time.Now().Add(2*time.Second))
	s.caller = sharedIdentityKey(t, profile.PQPure, "another caller")
	_, second := s.call(t, link.NodeID(), servedProcedure, cbor.Text("over"), time.Now().Add(2*time.Second))
	if code := replyCode(t, s.nextOther(t), second); code != "share_full" {
		t.Errorf("the second request: %q, want share_full", code)
	}
}

// Links of one node share one event dedup: a publication heard on two links is
// delivered once.
func TestLinksSharingADedupDeliverAnEventOnce(t *testing.T) {
	dedup := NewEventDedup()
	c := newClient(t, profile.PQPure)
	links := make([]*Link, 2)
	stations := make([]*testStation, 2)
	var publishes = make(chan cbor.Value, 1)
	for i := range links {
		stations[i] = startTestStation(t, profile.PQPure, "")
		link, err := dialWith(t, stations[i], c, func(cfg *Config) { cfg.Dedup = dedup })
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		links[i] = link
		controls := make(chan cbor.Value, 8)
		stations[i].relay(t, controls, func(publish cbor.Value) []cbor.Value {
			publishes <- publish
			return nil
		})
	}
	var subs []*Subscription
	for _, link := range links {
		sub, err := link.Subscribe(testRealm, testTopic)
		if err != nil {
			t.Fatalf("Subscribe: %v", err)
		}
		subs = append(subs, sub)
	}
	if err := links[0].Publish(Publication{Realm: testRealm, Topic: testTopic, Payload: cbor.Text("once")}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	event := cbor.Encode(eventOf(<-publishes))
	for _, s := range stations {
		s.send(event)
	}
	heard := 0
	deadline := time.After(time.Second)
	for heard < 2 {
		select {
		case <-subs[0].Events():
			heard++
		case <-subs[1].Events():
			heard++
		case <-deadline:
			if heard != 1 {
				t.Errorf("heard %d times, want once", heard)
			}
			return
		}
	}
	t.Errorf("heard %d times, want once", heard)
}

// replyCode is the code of an ERROR answering request, "" for a RESULT.
func replyCode(t *testing.T, v cbor.Value, request frame.VerifiedRequest) string {
	t.Helper()
	reply, err := frame.VerifyReply(v, request, profile.PQPure)
	if err != nil {
		t.Fatalf("the reply: %v", err)
	}
	return reply.Code
}
