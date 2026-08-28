//go:build live

// Integration tests against a real, live macula-station. NOT run by
// default `go test ./...` — gated behind the `live` build tag, since
// this depends on external infrastructure this module doesn't own or
// control (network reachability, the fleet's own uptime). Run
// explicitly:
//
//	go test -tags=live ./connection/... -run TestLive -v
//
// DNS gotcha, confirmed directly against the live box (carried over
// from macula-rust-sdk's own tests/live_station.rs, still true here):
// the bare macula.io hostname has an A (IPv4) record but no AAAA
// record, while station-de-frankfurt's actual QUIC listener is bound to
// a specific IPv6 address unrelated to that A record. Dialing
// "macula.io" resolves to a real, reachable IPv4 address with nothing
// listening on port 4433 — every packet vanishes silently.
// "station-de-frankfurt.macula.io" is the name that actually resolves
// to the listener.
package connection

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

func nowMs() int64 { return time.Now().UnixMilli() }

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}

const (
	liveStationHost = "station-de-frankfurt.macula.io"
	liveStationPort = 4433
)

// TestLiveHandshakeAgainstRealStation dials the real production fleet
// and completes a full CONNECT/HELLO handshake, WebPKI trust (the mode
// the live fleet actually presents — see transport.WebPKI's doc and
// plans/PLAN_WIRE_PROTOCOL.md §2's empirical note). Proves the whole
// stack this module built end to end: canonical CBOR, Ed25519 signing,
// the frame envelope, and the QUIC/TLS transport all interoperate with
// a real, unmodified macula-station — not just with themselves.
func TestLiveHandshakeAgainstRealStation(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	t.Logf("connected: remote=%s station_id=%x accepted=%v capabilities=%d negotiated=%d",
		session.RemoteAddr(), session.Station.StationID, session.Station.Accepted,
		session.Station.Capabilities, session.Station.NegotiatedCapabilities)

	if !session.Station.Accepted {
		t.Fatalf("station did not accept the connection (refusal_code=%v)", session.Station.RefusalCode)
	}
	if len(session.Station.NodeID) != 32 {
		t.Errorf("station NodeID length = %d, want 32", len(session.Station.NodeID))
	}
	if len(session.Station.StationID) != 32 {
		t.Errorf("station StationID length = %d, want 32", len(session.Station.StationID))
	}
}

// TestLiveCallRoundTrip is a real end-to-end CALL/RESULT-or-ERROR round
// trip. Calls a procedure name that certainly doesn't exist
// (macula_go_sdk.test_probe) — the point isn't to exercise any
// particular procedure, only to prove the wire round trip itself: a
// signed CALL sent, and a signed RESULT or ERROR received back,
// correlated by call_id, with a real BOLT#4 code if it's an error.
func TestLiveCallRoundTrip(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	realm := make([]byte, 32) // the content-sentinel realm, reused here as a harmless default
	response, err := session.Call("macula_go_sdk.test_probe", realm, cbor.Null(),
		nowMs()+10_000, id, 10*time.Second)
	if err != nil {
		t.Fatalf("Call: expected SOME response (result or a well-formed error), not: %v", err)
	}

	if response.IsError {
		t.Logf("OBSERVED: got an ERROR (expected for a nonexistent procedure): code=%d name=%s reported_by=%s detail=%v",
			response.Code, response.Name, hex.EncodeToString(response.ReportedBy), response.Detail)
	} else {
		t.Logf("OBSERVED: got a RESULT (unexpected for a made-up procedure, but valid): payload=%s responded_by=%s",
			response.Payload, hex.EncodeToString(response.RespondedBy))
	}
}

// TestLivePubSubRoundTrip is a real end-to-end SUBSCRIBE -> PUBLISH ->
// (maybe) EVENT round trip. Whether a subscriber receives its own
// publish is genuinely unknown going in — this test observes and
// reports rather than assuming an answer, same discipline as the
// unhardened-identity check in TestLiveHandshakeAgainstRealStation's
// sibling would use if this module built pubkey-pinned trust yet.
func TestLivePubSubRoundTrip(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	session, err := Connect(ctx, liveStationHost, liveStationPort, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer session.Close("normal", nil, id)

	// A realm+topic scratch value nobody else would collide with.
	realm := randomBytes(t, 32)
	topic := fmt.Sprintf("macula-go-sdk.test.%s", hex.EncodeToString(randomBytes(t, 8)))

	if err := session.Subscribe(frame.NewSubscribeSpec(topic, realm, id.NodeID()), id); err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	if err := session.Publish(frame.NewPublishSpec(topic, realm, id.NodeID(), 1,
		cbor.Text("hello from macula-go-sdk"), nowMs()), id); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	event, err := session.RecvEvent(5 * time.Second)
	if err != nil {
		t.Logf("OBSERVED: no EVENT arrived within 5s (%v) — a subscriber may not receive its "+
			"own publish, or delivery may simply be slower than this test waits. Not asserted "+
			"as a failure either way.", err)
		return
	}
	t.Logf("OBSERVED: received our own EVENT back — topic=%s seq=%d delivered_via=%s payload=%s",
		event.Topic, event.Seq, event.DeliveredVia, event.Payload)
	if event.Topic != topic {
		t.Errorf("event.Topic = %q, want %q", event.Topic, topic)
	}
}
