package identity

import "errors"

// ErrPostQuantumUnavailable is a key operation or dial in a binary built with
// GOFIPS140=v1.0.0. The FIPS 140-3 Go Cryptographic Module v1.0.0 has no
// ML-DSA, and every macula 11.0.0 profile signs with ML-DSA-87, so such a
// binary can neither sign with a node key nor check a station's certificate.
var ErrPostQuantumUnavailable = errors.New("identity: ML-DSA is unavailable: this binary was built with GOFIPS140=v1.0.0, whose FIPS 140-3 module has no ML-DSA; build without GOFIPS140 or with GOFIPS140=v1.26.0 or later")

// CheckPostQuantum returns ErrPostQuantumUnavailable when this binary was built
// against a FIPS 140-3 Go Cryptographic Module without ML-DSA, and nil
// otherwise. GenerateKey, LoadKey and transport.DialTarget check it first, so
// such a binary fails on its first key operation or dial with this error, not
// with one from inside a signature or a TLS handshake.
func CheckPostQuantum() error {
	if !mldsaInModule {
		return ErrPostQuantumUnavailable
	}
	return nil
}
