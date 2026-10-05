package transport

import (
	"context"
	"crypto/tls"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
)

// A profile dial to a live macula 12 station settles on SecP384r1MLKEM1024.
// The station's rustls picks the group from the client's offer, so this holds
// macula-go to what a real station negotiates, which a Go test station cannot
// stand in for. MACULA_GO_LIVE_STATION names the station as host:port, and
// MACULA_GO_LIVE_PROFILE its realm's profile (pq_hybrid when unset); the test
// is skipped without a station. It dials TLS alone: the node_id is the
// connection handshake's to compare, so the target's is a placeholder.
func TestDialTargetSettlesOnSecP384r1MLKEM1024WithALiveStation(t *testing.T) {
	station := os.Getenv("MACULA_GO_LIVE_STATION")
	if station == "" {
		t.Skip("MACULA_GO_LIVE_STATION is not set")
	}
	host, portText, err := net.SplitHostPort(station)
	if err != nil {
		t.Fatalf("MACULA_GO_LIVE_STATION %q: %v, want host:port", station, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("MACULA_GO_LIVE_STATION port %q: %v", portText, err)
	}
	p := profile.PQHybrid
	if name := os.Getenv("MACULA_GO_LIVE_PROFILE"); name != "" {
		p = profile.Profile(name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dialed, err := DialTarget(ctx, Target{Host: host, Port: uint16(port), Profile: p, ExpectedNodeID: [32]byte{1}})
	if err != nil {
		t.Fatalf("dial %s: %v", station, err)
	}
	defer func() { _ = dialed.Conn.CloseWithError(0, "test done") }()
	state := dialed.Conn.ConnectionState().TLS
	t.Logf("%s: group %s, suite %s", station, state.CurveID, tls.CipherSuiteName(state.CipherSuite))
	if state.CurveID != tls.SecP384r1MLKEM1024 {
		t.Fatalf("the dial to %s settled on %s, want SecP384r1MLKEM1024", station, state.CurveID)
	}
}
