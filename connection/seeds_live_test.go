//go:build live

// Integration tests for ConnectSeeds and Session.Done, added alongside
// the multi-seed dial-fallback + disconnect-signal support (see
// live_test.go's own doc for why these are `live`-tagged rather than
// using a local fake station — this repo has no such test double, and
// these behaviors only mean something against a real QUIC/TLS
// handshake). Run explicitly:
//
//	go test -tags=live ./connection/... -run TestLiveSeeds -v
package connection

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// TestLiveConnectSeedsFallsThroughDeadSeed proves ConnectSeeds tries
// every candidate in order rather than giving up after the first
// failure: seed 1 targets a local UDP port nothing is listening on
// (fails fast on Linux via ICMP port-unreachable), seed 2 is the real
// live station. A generous outer deadline absorbs slower failure modes
// on platforms where that ICMP signal doesn't arrive quickly, without
// making the test flaky.
func TestLiveConnectSeedsFallsThroughDeadSeed(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	seeds := []Seed{
		{Host: "127.0.0.1", Port: 1}, // nothing listens here
		{Host: liveStationHost, Port: liveStationPort},
	}
	session, err := ConnectSeeds(ctx, seeds, transport.WebPKI{}, id)
	if err != nil {
		t.Fatalf("ConnectSeeds: %v", err)
	}
	defer session.Close("normal", nil, id)

	if !session.Station.Accepted {
		t.Fatalf("station did not accept the connection (refusal_code=%v)", session.Station.RefusalCode)
	}
	t.Logf("fell through dead seed to: %s", session.RemoteAddr())
}

// TestLiveConnectSeedsAllDeadNamesEverySeed asserts the all-failed
// error names every seed tried — the direct fix for
// feedback_three_seed_stations_minimum's core complaint that a
// misconfigured seed fails silently.
func TestLiveConnectSeedsAllDeadNamesEverySeed(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	seeds := []Seed{
		{Host: "127.0.0.1", Port: 1},
		{Host: "127.0.0.1", Port: 2},
	}
	_, err = ConnectSeeds(ctx, seeds, transport.WebPKI{}, id)
	if err == nil {
		t.Fatalf("ConnectSeeds: expected an error, got nil")
	}
	for _, want := range []string{"127.0.0.1:1", "127.0.0.1:2"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention failed seed %q", err.Error(), want)
		}
	}
}

// TestLiveSessionDoneFiresOnClose proves Session.Done's channel closes
// once the connection is gone — here, the caller-initiated Close path.
// The other half of Done's purpose (the station's side dying
// unexpectedly) isn't something this repo's tests can safely trigger
// against shared, live infrastructure; that path is covered by manual
// smoke-testing against a station a developer controls (see the plan
// this feature shipped under).
func TestLiveSessionDoneFiresOnClose(t *testing.T) {
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

	select {
	case <-session.Done():
		t.Fatalf("Done() fired before Close was called")
	default:
	}

	if err := session.Close("normal", nil, id); err != nil {
		t.Fatalf("Close: %v", err)
	}

	select {
	case <-session.Done():
	case <-time.After(2 * time.Second):
		t.Fatalf("Done() did not fire within 2s of Close")
	}
}
