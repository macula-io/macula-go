package stationlink

import (
	"bytes"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

var testRealm = [32]byte{3}

const testTopic = "io.macula/mcl-news/news/wire/news_item_reported_v1"

// eventOf is the EVENT a station makes from a PUBLISH: the same publication,
// delivered directly.
func eventOf(publish cbor.Value) cbor.Value {
	publication, _ := publish.Get("publication")
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(frame.ProtocolVersion)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text("event")},
		{Key: cbor.Text("publication"), Val: publication},
		{Key: cbor.Text("delivered_via"), Val: cbor.Text("direct")},
	})
}

// relay reads the client's frames at the station: it opens each control frame
// from its neighbour signature (the SUBSCRIBE and UNSUBSCRIBE a client sends),
// hands each on to controls, and answers each PUBLISH with the EVENTs deliver
// makes of it.
func (s *testStation) relay(t *testing.T, controls chan<- cbor.Value, deliver func(cbor.Value) []cbor.Value) {
	s.waitAccepted()
	go func() {
		seq := uint64(0)
		for raw := range s.received {
			v, err := cbor.Decode(raw)
			if err != nil {
				continue
			}
			frameType, _ := fieldOfTest(v, "frame_type").AsText()
			if frameType == "publish" {
				for _, event := range deliver(v) {
					s.send(cbor.Encode(event))
				}
				continue
			}
			opened, err := frame.VerifyNeighbour(v, frame.NeighbourPeer{Profile: s.profile, PeerKey: s.client.IdentityKey, Connection: s.connection, Seq: seq})
			if err != nil {
				t.Errorf("station: a control frame that does not open: %v", err)
				continue
			}
			if frame.NeighbourSigned(s.profile, frameType) {
				seq++
			}
			controls <- opened
		}
	}()
}

func nextControl(t *testing.T, controls <-chan cbor.Value) cbor.Value {
	t.Helper()
	select {
	case v := <-controls:
		return v
	case <-time.After(10 * time.Second):
		t.Fatal("no control frame at the station")
		return cbor.Value{}
	}
}

// A subscriber hears its own publication back as a verified event, once, even
// when the station delivers it twice; its SUBSCRIBE names its realm, the topic
// as bytes and itself.
func TestASubscriberHearsAVerifiedEventOnce(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s := linkWithStation(t, p)
			controls := make(chan cbor.Value, 8)
			s.relay(t, controls, func(publish cbor.Value) []cbor.Value {
				return []cbor.Value{eventOf(publish), eventOf(publish)}
			})
			sub, err := link.Subscribe(testRealm, testTopic)
			if err != nil {
				t.Fatalf("Subscribe: %v", err)
			}
			subscribe := nextControl(t, controls)
			topic, _ := fieldOfTest(subscribe, "topic").AsBytes()
			subscriber, _ := fieldOfTest(subscribe, "subscriber").AsBytes()
			self := link.NodeID()
			if name, _ := fieldOfTest(subscribe, "frame_type").AsText(); name != "subscribe" ||
				string(topic) != testTopic || !bytes.Equal(subscriber, self[:]) {
				t.Errorf("the SUBSCRIBE: %v", subscribe)
			}
			if err := link.Publish(Publication{Realm: testRealm, Topic: testTopic, Payload: cbor.Text("headline")}); err != nil {
				t.Fatalf("Publish: %v", err)
			}
			select {
			case event := <-sub.Events():
				if text, _ := event.Payload.AsText(); text != "headline" || event.Publisher != self || event.DeliveredVia != "direct" {
					t.Errorf("event %+v", event)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("no event")
			}
			select {
			case event := <-sub.Events():
				t.Errorf("a second delivery of the same publication: %+v", event)
			case <-time.After(300 * time.Millisecond):
			}
		})
	}
}

// An event on a topic nobody here subscribed to is counted, not delivered;
// one whose publication does not verify is dropped.
func TestEventsThatDoNotBelongAreNotDelivered(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(publish cbor.Value) []cbor.Value {
		publication, _ := publish.Get("publication")
		tbs, _ := publication.Get("tbs")
		raw, _ := tbs.AsBytes()
		tampered := append([]byte{}, raw...)
		tampered[len(tampered)-1] ^= 1
		key, _ := publication.Get("key")
		signature, _ := publication.Get("signature")
		forged := cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("version"), Val: cbor.Int(frame.ProtocolVersion)},
			{Key: cbor.Text("frame_type"), Val: cbor.Text("event")},
			{Key: cbor.Text("publication"), Val: cbor.Map([]cbor.MapEntry{
				{Key: cbor.Text("key"), Val: key}, {Key: cbor.Text("tbs"), Val: cbor.Bytes(tampered)},
				{Key: cbor.Text("signature"), Val: signature}})},
			{Key: cbor.Text("delivered_via"), Val: cbor.Text("direct")},
		})
		return []cbor.Value{forged, eventOf(publish)}
	})
	sub, err := link.Subscribe(testRealm, "some/other/topic")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	nextControl(t, controls)
	if err := link.Publish(Publication{Realm: testRealm, Topic: testTopic, Payload: cbor.Text("x")}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	deadline := time.After(10 * time.Second)
	for link.Unrouted()["event_unsubscribed"] < 1 || link.Unrouted()["event_unverified"] < 1 {
		select {
		case <-deadline:
			t.Fatalf("unrouted %v, want one event_unsubscribed and one event_unverified", link.Unrouted())
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case event := <-sub.Events():
		t.Errorf("an event for another topic was delivered: %+v", event)
	default:
	}
}

// Unsubscribing sends UNSUBSCRIBE for the same realm and topic.
func TestUnsubscribeSendsUnsubscribe(t *testing.T) {
	link, s := linkWithStation(t, profile.PQHybrid)
	controls := make(chan cbor.Value, 8)
	s.relay(t, controls, func(cbor.Value) []cbor.Value { return nil })
	sub, err := link.Subscribe(testRealm, testTopic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	nextControl(t, controls)
	if err := sub.Unsubscribe(); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	unsubscribe := nextControl(t, controls)
	if name, _ := fieldOfTest(unsubscribe, "frame_type").AsText(); name != "unsubscribe" {
		t.Errorf("after Unsubscribe the station saw %q", name)
	}
}
