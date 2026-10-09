package ucan

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// A binary built with GOFIPS140=v1.0.0 cannot check an ML-DSA signature, so
// Authorize says so instead of refusing the token as a signature that does not
// verify, or as malformed. In any other binary the same token authorizes as
// macula's vector says. Which way a run goes is read from crypto/fips140, not
// from the check under test. CI runs this test both ways.
func TestAuthorizeSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	v := loadVectors(t)
	var ok vectorCase
	for _, c := range v.Profiles["pq_pure"].Cases {
		if c.Verdict == "ok" {
			ok = c
			break
		}
	}
	_, err := Authorize([]byte(ok.Token), ok.Policy.policy(t), ok.context(t, profile.PQPure))
	_, malformedErr := Authorize([]byte("not a token"), ok.Policy.policy(t), ok.context(t, profile.PQPure))
	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		for name, e := range map[string]error{"a token macula accepts": err, "a malformed token": malformedErr} {
			if !errors.Is(e, identity.ErrPostQuantumUnavailable) || RefusalName(e) != "" {
				t.Errorf("%s with the module %s: %v, want ErrPostQuantumUnavailable alone", name, fips140.Version(), e)
			}
		}
		return
	}
	if err != nil || !errors.Is(malformedErr, ErrMalformed) {
		t.Errorf("with the module %s: %v and %v, want ok and malformed", fips140.Version(), err, malformedErr)
	}
}

// macula#87: base58 decodes in time quadratic in its length, ahead of the
// signature check, so a did:key longer than any carried key's is refused
// before it is decoded.
func TestAnOverlongDIDKeyIsRefusedAtOnce(t *testing.T) {
	did := "did:key:z" + strings.Repeat("2", 200_000)
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		started := time.Now()
		if _, err := CarriedKey(did, p); !errors.Is(err, ErrMalformed) {
			t.Fatalf("%v: %v", p, err)
		}
		if took := time.Since(started); took > 100*time.Millisecond {
			t.Fatalf("%v: refused after %v", p, took)
		}
	}
}
