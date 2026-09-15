package identity

import (
	"crypto/fips140"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// withoutMLDSA reports whether this test binary was built against the FIPS
// 140-3 Go Cryptographic Module v1.0.0, read from crypto/fips140 and not from
// the check under test.
func withoutMLDSA() bool { return strings.HasPrefix(fips140.Version(), "v1.0.") }

// A binary built with GOFIPS140=v1.0.0 has no ML-DSA, and says so on its first
// key operation: CheckPostQuantum, GenerateKey, GenerateIdentityKey and LoadKey
// return ErrPostQuantumUnavailable, LoadKey before it reads the file. Any other
// binary generates keys and reads key files. CI runs this test both ways.
func TestAKeyOperationSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no key file here")
	_, generateErr := GenerateKey(PurposeConnect, profile.PQPure)
	_, identityErr := GenerateIdentityKey(profile.PQPure, 0)
	_, loadErr := LoadKey(missing, PurposeConnect, profile.PQPure)
	checkErr := CheckPostQuantum()

	if withoutMLDSA() {
		for name, err := range map[string]error{
			"CheckPostQuantum":    checkErr,
			"GenerateKey":         generateErr,
			"GenerateIdentityKey": identityErr,
			"LoadKey":             loadErr,
		} {
			if !errors.Is(err, ErrPostQuantumUnavailable) {
				t.Errorf("%s with the module %s: %v, want ErrPostQuantumUnavailable", name, fips140.Version(), err)
			}
		}
		return
	}
	if checkErr != nil || generateErr != nil || identityErr != nil {
		t.Errorf("with the module %s: CheckPostQuantum %v, GenerateKey %v, GenerateIdentityKey %v, want no errors",
			fips140.Version(), checkErr, generateErr, identityErr)
	}
	if !errors.Is(loadErr, fs.ErrNotExist) {
		t.Errorf("LoadKey of a missing file with the module %s: %v, want it not found", fips140.Version(), loadErr)
	}
}

// A binary built with GOFIPS140=v1.0.0 cannot check an ML-DSA signature, so
// each verifier that returns an error says so instead of blaming the signature:
// VerifyTLSBinding, VerifyConnectBinding, VerifyStatus, VerifyObject and
// VerifyHeldObject return ErrPostQuantumUnavailable. In any other binary the
// same inputs reach the signature check and are refused as invalid signatures.
// CI runs this test both ways.
func TestAVerifierSaysWhetherTheBinaryHasMLDSA(t *testing.T) {
	carried := make([]byte, mldsaPublicKeySize)
	tbs := cbor.Encode(cbor.Map(nil))
	signature := make([]byte, SignatureSize(profile.PQPure))
	signed := SignedTBS{TBS: tbs, Signature: signature}
	_, tlsErr := VerifyTLSBinding(signed, carried, profile.PQPure, []byte("a leaf"), 0)
	_, connectErr := VerifyConnectBinding(signed, carried, profile.PQPure, carried, 0)
	_, statusErr := VerifyStatus(signed, signed, carried, profile.PQPure, 0)
	_, objectErr := VerifyObject("MACULA-PQ-RECORD-V1", Object{Key: carried, TBS: tbs, Signature: signature}.Value(), profile.PQPure)
	_, heldErr := VerifyHeldObject("MACULA-PQ-RECORD-V1", HeldObject{TBS: tbs, Signature: signature}.Value(), carried, profile.PQPure)

	cases := []struct {
		name    string
		err     error
		invalid error
	}{
		{"VerifyTLSBinding", tlsErr, ErrBindingSignatureInvalid},
		{"VerifyConnectBinding", connectErr, ErrBindingSignatureInvalid},
		{"VerifyStatus", statusErr, ErrStatusSignatureInvalid},
		{"VerifyObject", objectErr, ErrObjectSignatureInvalid},
		{"VerifyHeldObject", heldErr, ErrObjectSignatureInvalid},
	}
	for _, c := range cases {
		want := c.invalid
		if withoutMLDSA() {
			want = ErrPostQuantumUnavailable
		}
		if !errors.Is(c.err, want) {
			t.Errorf("%s with the module %s: %v, want %v", c.name, fips140.Version(), c.err, want)
		}
	}
}
