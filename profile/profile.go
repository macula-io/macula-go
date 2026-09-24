// Package profile names the post-quantum crypto profile a node runs and the
// algorithms of each, the Go counterpart of macula's macula_crypto_profile. A
// realm runs one profile and every node in it is configured with that one:
// there is no default, no negotiation and no classical fallback.
package profile

import (
	"crypto/tls"
	"errors"
	"fmt"
)

// Profile is a crypto profile, by the name a node is configured with.
type Profile string

const (
	// PQPure is the CNSA 2.0 profile: ML-DSA-87 signatures, with no classical
	// half. Its connections negotiate transport.KeyExchangeGroups, as every
	// macula 12 node's do.
	PQPure Profile = "pq_pure"
	// PQHybrid is the hybrid profile: ML-DSA-87 alone in TLS, and every other
	// signature the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512, valid only
	// if both halves verify.
	PQHybrid Profile = "pq_hybrid"
)

var (
	// ErrMissing is a node configured with no profile.
	ErrMissing = errors.New("profile: no crypto profile is configured")
	// ErrUnknown is a value that is not exactly one known profile.
	ErrUnknown = errors.New("profile: not a known crypto profile")
)

// Definition is what a profile uses.
type Definition struct {
	// TLSSignatureScheme is the signature scheme of a station's TLS leaf,
	// ML-DSA-87 in both profiles.
	TLSSignatureScheme tls.SignatureScheme
	// Hybrid reports whether identity, CONNECT and status signatures pair
	// ML-DSA-87 with RSA-PSS-4096.
	Hybrid bool
	// SigAlg is the signature algorithm's name, as signed structures carry it.
	SigAlg string
}

// Parse is the profile a configured value names. An empty value is
// ErrMissing, and anything but exactly "pq_pure" or "pq_hybrid" is ErrUnknown.
func Parse(value string) (Profile, error) {
	if value == "" {
		return "", ErrMissing
	}
	p := Profile(value)
	if _, err := p.Definition(); err != nil {
		return "", err
	}
	return p, nil
}

// Definition is p's algorithms, or ErrUnknown when p is not a known profile.
func (p Profile) Definition() (Definition, error) {
	switch p {
	case PQPure:
		return Definition{
			TLSSignatureScheme: tls.MLDSA87,
			SigAlg:             "ML-DSA-87",
		}, nil
	case PQHybrid:
		return Definition{
			TLSSignatureScheme: tls.MLDSA87,
			Hybrid:             true,
			SigAlg:             "ML-DSA-87-PS384",
		}, nil
	default:
		return Definition{}, fmt.Errorf("%w: %q", ErrUnknown, string(p))
	}
}
