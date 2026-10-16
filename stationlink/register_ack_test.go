package stationlink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

// Serve and Subscribe return the station's verdict on their registration
// (REGISTER_ACK, WIRE_1_0.md section 3.5, macula#12), as macula 15's advertise
// and subscribe do.

// refusing is a verdict that refuses kind with reason and accepts the rest.
func refusing(kind, reason string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if k == kind {
			return reason, false
		}
		return "", false
	}
}

// silentOn is a verdict that sends no ack for kind and accepts the rest.
func silentOn(kind string) func(string) (string, bool) {
	return func(k string) (string, bool) { return "", k == kind }
}

func advertisementsPut(s *servingStation) int {
	s.dht.mu.Lock()
	defer s.dht.mu.Unlock()
	return len(s.dht.byType[record.TypeProcedureAdvertisement])
}

func TestServeReturnsTheStationsRefusalAndPutsNothing(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	s.judge(refusing("advertise", "too_many_providers"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	offer := Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo, RealmKey: fixture.realm.PublicKey()}
	served, err := link.Serve(ctx, offer)
	var refused *RefusedError
	if !errors.As(err, &refused) || served != nil {
		t.Fatalf("Serve: %v, %v; want a *RefusedError", served, err)
	}
	if refused.Kind != "advertise" || refused.Realm != servedRealm || refused.Name != servedProcedure ||
		refused.Reason != "too_many_providers" || refused.Station != s.nodeID {
		t.Errorf("the refusal %+v", refused)
	}
	if n := advertisementsPut(s); n != 0 {
		t.Errorf("a refused advertisement was put in the DHT %d times", n)
	}
	s.judge(nil)
	if _, err := link.Serve(ctx, offer); err != nil {
		t.Errorf("Serve after the refusal: %v, want it served", err)
	}
	if n := advertisementsPut(s); n != 1 {
		t.Errorf("an accepted advertisement was put in the DHT %d times, want once", n)
	}
}

func TestServeWithNoAckIsUnacknowledgedAndWithdrawn(t *testing.T) {
	defer SetRegisterAckTimeout(300 * time.Millisecond)()
	link, s, fixture := startServing(t, profile.PQPure)
	s.judge(silentOn("advertise"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	served, err := link.Serve(ctx, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo,
		RealmKey: fixture.realm.PublicKey()})
	var silent *UnacknowledgedError
	if !errors.As(err, &silent) || served != nil {
		t.Fatalf("Serve: %v, %v; want an *UnacknowledgedError", served, err)
	}
	if silent.Kind != "advertise" || silent.Name != servedProcedure || silent.Station != s.nodeID {
		t.Errorf("the error %+v", silent)
	}
	for _, want := range []string{"advertise", "unadvertise"} {
		if got, _ := fieldOfTest(s.nextControl(t), "frame_type").AsText(); got != want {
			t.Errorf("the station saw %q, want %q", got, want)
		}
	}
}

// Serve within a context that ends before the ack returns the context's error.
func TestServeEndsWithItsContext(t *testing.T) {
	link, s, fixture := startServing(t, profile.PQPure)
	s.judge(silentOn("advertise"))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := link.Serve(ctx, Offer{Realm: servedRealm, Procedure: servedProcedure, Handler: echo,
		RealmKey: fixture.realm.PublicKey()})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Serve: %v, want context.DeadlineExceeded", err)
	}
}

func TestSubscribeReturnsTheStationsRefusal(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(cbor.Value) []cbor.Value { return nil })
	s.judge(refusing("subscribe", "not_authorized"))
	sub, err := link.Subscribe(testRealm, testTopic)
	var refused *RefusedError
	if !errors.As(err, &refused) || sub != nil {
		t.Fatalf("Subscribe: %v, %v; want a *RefusedError", sub, err)
	}
	if refused.Kind != "subscribe" || refused.Realm != testRealm || refused.Name != testTopic ||
		refused.Reason != "not_authorized" || refused.Station != s.nodeID {
		t.Errorf("the refusal %+v", refused)
	}
	s.judge(nil)
	if _, err := link.Subscribe(testRealm, testTopic); err != nil {
		t.Errorf("Subscribe after the refusal: %v", err)
	}
	for _, want := range []string{"subscribe", "subscribe"} {
		if got, _ := fieldOfTest(nextControl(t, controls), "frame_type").AsText(); got != want {
			t.Errorf("the station saw %q, want %q", got, want)
		}
	}
}

// An ack naming another subscriber answers nothing of this link's: the link
// registers only its own node.
func TestSubscribeWithNoAckOfItsOwnIsUnacknowledgedAndWithdrawn(t *testing.T) {
	defer SetRegisterAckTimeout(500 * time.Millisecond)()
	link, s := linkWithStation(t, profile.PQPure)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(cbor.Value) []cbor.Value { return nil })
	s.judge(silentOn("subscribe"))
	type answer struct {
		sub *Subscription
		err error
	}
	answered := make(chan answer, 1)
	go func() {
		sub, err := link.Subscribe(testRealm, testTopic)
		answered <- answer{sub, err}
	}()
	nextControl(t, controls)
	foreign, err := frame.RegisterAckFrame(frame.RegisterAck{Kind: "subscribe", Realm: testRealm, Name: testTopic,
		Subscriber: [32]byte{0xEE}, Accepted: true})
	if err != nil {
		t.Fatal(err)
	}
	s.send(cbor.Encode(foreign))
	got := <-answered
	var silent *UnacknowledgedError
	if !errors.As(got.err, &silent) || got.sub != nil {
		t.Fatalf("Subscribe: %v, %v; want an *UnacknowledgedError", got.sub, got.err)
	}
	if silent.Kind != "subscribe" || silent.Name != testTopic || silent.Station != s.nodeID {
		t.Errorf("the error %+v", silent)
	}
	if got, _ := fieldOfTest(nextControl(t, controls), "frame_type").AsText(); got != "unsubscribe" {
		t.Errorf("after no ack the station saw %q, want unsubscribe", got)
	}
}

// A second subscription to a topic whose SUBSCRIBE is still unanswered waits
// for the same verdict, and sends no SUBSCRIBE of its own.
func TestASecondSubscriberSharesTheFirstsVerdict(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(cbor.Value) []cbor.Value { return nil })
	s.judge(silentOn("subscribe"))
	answered := make(chan error, 2)
	for range 2 {
		go func() {
			_, err := link.Subscribe(testRealm, testTopic)
			answered <- err
		}()
	}
	nextControl(t, controls)
	refusal, err := frame.RegisterAckFrame(frame.RegisterAck{Kind: "subscribe", Realm: testRealm, Name: testTopic,
		Subscriber: link.NodeID(), Reason: "too_many_realms"})
	if err != nil {
		t.Fatal(err)
	}
	s.send(cbor.Encode(refusal))
	for range 2 {
		var refused *RefusedError
		if err := <-answered; !errors.As(err, &refused) || refused.Reason != "too_many_realms" {
			t.Errorf("Subscribe: %v, want the station's refusal", err)
		}
	}
	select {
	case extra := <-controls:
		t.Errorf("the station saw a second frame: %v", extra)
	case <-time.After(200 * time.Millisecond):
	}
}
