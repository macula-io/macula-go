package identity

import (
	"errors"

	"github.com/macula-io/macula-go/profile"
)

// ErrPostQuantumUnavailable is a key operation, a signature check or a dial in
// a binary built against the FIPS 140-3 Go Cryptographic Module v1.0.0
// (GOFIPS140=v1.0.0, or GOFIPS140=certified at Go 1.27). That module has no
// ML-DSA, and every macula 12 profile signs with ML-DSA-87, so such a
// binary can neither sign with a node key nor check a signature or a station's
// certificate.
var ErrPostQuantumUnavailable = errors.New("identity: ML-DSA is unavailable: this binary was built against the FIPS 140-3 Go Cryptographic Module v1.0.0 (GOFIPS140=v1.0.0, or GOFIPS140=certified at Go 1.27), which has no ML-DSA; build without GOFIPS140 or with GOFIPS140=v1.26.0 or later")

// CheckPostQuantum returns ErrPostQuantumUnavailable when this binary was built
// against a FIPS 140-3 Go Cryptographic Module without ML-DSA, and nil
// otherwise. GenerateKey, LoadKey, every verifier that returns an error, and
// transport.DialTarget check it first, so such a binary fails with this error,
// not with one that blames a signature or a TLS handshake.
func CheckPostQuantum() error {
	if !mldsaInModule {
		return ErrPostQuantumUnavailable
	}
	return nil
}

// verifySignature is the signature check every verifier that returns an error
// shares: ErrPostQuantumUnavailable in a binary without ML-DSA, invalid when
// signature is not carriedKey's signature over message under profile p, and
// nil otherwise.
func verifySignature(message, signature, carriedKey []byte, p profile.Profile, invalid error) error {
	if err := CheckPostQuantum(); err != nil {
		return err
	}
	if !Verify(message, signature, carriedKey, p) {
		return invalid
	}
	return nil
}
