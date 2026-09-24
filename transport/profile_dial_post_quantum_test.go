package transport

import (
	"context"
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// A binary built with GOFIPS140=v1.0.0 has no ML-DSA, so it could not check a
// station's leaf: DialTarget refuses every target before dialing, with
// identity.ErrPostQuantumUnavailable. Any other binary dials a station of the
// profile. CI runs this test both ways; which way a run goes is read from
// crypto/fips140, not from the check under test.
func TestDialTargetSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		started := time.Now()
		// 192.0.2.1 is TEST-NET-1: a dial there would wait for the context.
		_, err := DialTarget(ctx, Target{Host: "192.0.2.1", Port: 4433, Profile: profile.PQPure, ExpectedNodeID: [32]byte{1}})
		if !errors.Is(err, identity.ErrPostQuantumUnavailable) {
			t.Fatalf("DialTarget with the module %s: %v, want identity.ErrPostQuantumUnavailable", fips140.Version(), err)
		}
		if waited := time.Since(started); waited > 500*time.Millisecond {
			t.Fatalf("DialTarget returned after %s, want it refused before dialing", waited)
		}
		return
	}
	station := startStation(t, stationSpec{groups: KeyExchangeGroups[:1], key: mldsa87Key(t)})
	if _, err := dialWithin(t, targetFor(station, profile.PQPure)); err != nil {
		t.Fatalf("DialTarget with the module %s: %v, want the station reached", fips140.Version(), err)
	}
}
