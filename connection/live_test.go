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
	"testing"
	"time"

	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
)

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
	defer session.Close()

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
