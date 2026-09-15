package profile

import (
	"crypto/tls"
	"errors"
	"testing"
)

func TestParseAcceptsExactlyTheTwoProfiles(t *testing.T) {
	for _, want := range []Profile{PQPure, PQHybrid} {
		got, err := Parse(string(want))
		if err != nil || got != want {
			t.Errorf("Parse(%q) = (%q, %v), want the profile", want, got, err)
		}
	}
}

// There is no default profile: a node that names none does not start.
func TestParseRefusesAMissingProfile(t *testing.T) {
	if _, err := Parse(""); !errors.Is(err, ErrMissing) {
		t.Fatalf("Parse(\"\") = %v, want ErrMissing", err)
	}
}

func TestParseRefusesEveryOtherValue(t *testing.T) {
	for _, value := range []string{"classical", "PQ_PURE", "pq_pure,pq_hybrid", " pq_pure", "rsa_only"} {
		if _, err := Parse(value); !errors.Is(err, ErrUnknown) {
			t.Errorf("Parse(%q) = %v, want ErrUnknown", value, err)
		}
	}
}

// Each profile uses one key exchange group, the ML-DSA-87 TLS signature
// scheme and the AES-256 suite, all at level 5, and pq_hybrid pairs every
// other signature with RSA-PSS-4096.
func TestEachProfileUsesItsLevel5Algorithms(t *testing.T) {
	cases := []struct {
		p      Profile
		group  tls.CurveID
		hybrid bool
		sigAlg string
	}{
		{PQPure, tls.MLKEM1024, false, "ML-DSA-87"},
		{PQHybrid, tls.SecP384r1MLKEM1024, true, "ML-DSA-87-PS384"},
	}
	for _, c := range cases {
		d, err := c.p.Definition()
		if err != nil {
			t.Fatalf("%s: %v", c.p, err)
		}
		if d.KeyExchangeGroup != c.group || d.TLSSignatureScheme != tls.MLDSA87 ||
			d.TLSCipherSuite != tls.TLS_AES_256_GCM_SHA384 || d.Hybrid != c.hybrid || d.SigAlg != c.sigAlg {
			t.Errorf("%s: definition %+v", c.p, d)
		}
	}
}

func TestAnUnknownProfileHasNoDefinition(t *testing.T) {
	if _, err := Profile("rsa_only").Definition(); !errors.Is(err, ErrUnknown) {
		t.Fatalf("Definition of an unknown profile: %v, want ErrUnknown", err)
	}
}
