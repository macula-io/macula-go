//go:build live

// Live-fleet station-discovery test -- run explicitly:
//
//	go test -tags=live ./pool/... -run TestLiveStationDiscovery -v
package pool

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

func TestLiveStationDiscoveryFindsRealStationsFromHecateStations(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	p, err := Connect(context.Background(),
		[]Seed{{Host: liveStationHost, Port: liveStationPort}},
		Opts{
			Identity: id,
			Trust:    transport.WebPKI{},
			StationDiscovery: StationDiscoveryOpts{
				Enabled:         true,
				RefreshInterval: time.Hour, // one attempt is enough for this test
				MaxLinks:        5,
			},
		})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, 5*time.Second, func() bool { return p.Status().HealthyLinks >= 1 })

	// Give the background discovery goroutine time to run its first
	// attempt (DHT lookup + list_stations call, both real network round
	// trips against station-de-frankfurt.macula.io) -- this only proves
	// discovery ITSELF worked (addLink was called for real stations),
	// not that any of them are reachable/healthy yet.
	waitFor(t, 15*time.Second, func() bool { return p.linkCount() > 1 })

	linkCount := p.linkCount()
	if linkCount <= 1 {
		t.Fatalf(
			"station discovery found no additional stations against the real fleet (linkCount=%d, want >1) -- "+
				"either hecate_stations.list_stations isn't currently advertised/visible from %s, or discovery has a real bug",
			linkCount, liveStationHost,
		)
	}
	t.Logf("discovery found linkCount=%d, waiting for their handshakes to complete", linkCount)

	// SEPARATE budget for the newly discovered links' own dial+handshake
	// against real remote hosts -- distinct from the discovery round
	// trip above, so a slow/partially-unreachable station doesn't get
	// blamed on discovery logic itself.
	waitFor(t, 20*time.Second, func() bool { return p.Status().HealthyLinks >= 2 })
	healthy := p.Status().HealthyLinks
	t.Logf("after live discovery: linkCount=%d healthyLinks=%d", linkCount, healthy)
	if healthy < 2 {
		t.Fatalf("discovered link(s) exist (linkCount=%d) but didn't come up healthy within the wait window (healthy=%d)", linkCount, healthy)
	}
}
