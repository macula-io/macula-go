package teststation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
)

func dial(t *testing.T, s *Station, name string) *stationlink.Link {
	t.Helper()
	key := Key(t, s.Profile, name)
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := stationlink.Dial(ctx, stationlink.Config{Target: s.Target(), IdentityKey: key, Issuer: issuer})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = link.Close("test_done") })
	s.WaitAccepted()
	return link
}

// The station answers as one does: its own endpoint is in its DHT, ping is its
// relay error, an unadvertised procedure is unknown_next_peer, and a PUBLISH
// comes back to its subscriber as an EVENT.
func TestTheStationAnswersAsAStationDoes(t *testing.T) {
	s := Start(t, profile.PQPure, "smoke")
	link := dial(t, s, "smoke client")
	ctx := t.Context()
	endpoint, err := link.FindRecord(ctx, record.StationEndpointKey(s.NodeID))
	if err != nil || endpoint.Record().KeyID != s.NodeID {
		t.Errorf("its endpoint: %v", err)
	}
	var relay *stationlink.RelayError
	if _, err := link.Call(ctx, stationlink.Call{Procedure: "_macula.ping", Payload: cbor.Map(nil)}); !errors.As(err, &relay) || relay.Code != "unknown_next_peer" {
		t.Errorf("ping: %v", err)
	}
	if _, err := link.Call(ctx, stationlink.Call{Realm: [32]byte{1}, Procedure: "org/nothing", Target: [32]byte{2}, Payload: cbor.Map(nil)}); !errors.As(err, &relay) || relay.Code != "unknown_next_peer" {
		t.Errorf("an unadvertised procedure: %v", err)
	}
	sub, err := link.Subscribe([32]byte{1}, "org/topic")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := link.Publish(stationlink.Publication{Realm: [32]byte{1}, Topic: "org/topic", Payload: cbor.Text("hi")}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case event := <-sub.Events():
		if text, _ := event.Payload.AsText(); text != "hi" {
			t.Errorf("event %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Error("no event")
	}
}

// Drop ends a client's connection.
func TestDropEndsTheClientsLink(t *testing.T) {
	s := Start(t, profile.PQPure, "drop")
	link := dial(t, s, "drop client")
	s.Drop(link.NodeID())
	select {
	case <-link.Done():
	case <-time.After(5 * time.Second):
		t.Error("the link outlived its connection")
	}
}
