package handshake

import (
	"crypto/fips140"
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// A binary built with GOFIPS140=v1.0.0 cannot check a peer's status statement,
// so ReadStatus says why: identity.ErrPostQuantumUnavailable. In any other
// binary the same frame reaches the signature check and is refused as an
// invalid signature. Which way a run goes is read from crypto/fips140, not from
// the check under test. CI runs this test both ways.
func TestReadStatusSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	statement := identity.SignedTBS{TBS: cbor.Encode(cbor.Map(nil)), Signature: make([]byte, identity.SignatureSize(profile.PQPure))}
	peer := Peer{Profile: profile.PQPure, IdentityKey: make([]byte, 2592), Binding: statement, NowMs: now}
	_, err := ReadStatus(StatusFrame(statement), peer)
	want := identity.ErrStatusSignatureInvalid
	if strings.HasPrefix(fips140.Version(), "v1.0.") {
		want = identity.ErrPostQuantumUnavailable
	}
	if !errors.Is(err, want) {
		t.Fatalf("ReadStatus with the module %s: %v, want %v", fips140.Version(), err, want)
	}
}
