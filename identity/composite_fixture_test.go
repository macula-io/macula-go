package identity

import (
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// lampsFixture is id-MLDSA87-RSA4096-PSS-SHA512 as the IETF LAMPS draft
// publishes it (draft-ietf-lamps-pq-composite-sigs, src/testvectors.json), and
// macula's zero-dropped composite over the same message and key: copied from
// macula v12.1.0's test/fixtures/lamps_mldsa87_rsa4096_pss_sha512 and
// test/fixtures/lamps_composite_zero_dropped, pinned by sha256 so a drifted
// copy fails here rather than passing on bytes nobody else signed.
var lampsFixture = map[string]string{
	"m.bin":                "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c",
	"pk.bin":               "88560e139b35d0738857f9c8e29bbcfb108e3539bd2bf6f4994bb4b34beb019d",
	"s.bin":                "95e17c93e9c1d6b5c3c4bae9d8687cd1606e232dca0af38e437e7e2e16894303",
	"zero_dropped_sig.bin": "4e43a85def2b0acec014724d7d4b23ac86685ef35f28a9be85d9aff4a7cd30cd",
}

func TestTheLAMPSFixtureIsTheOneMaculaPins(t *testing.T) {
	for name, want := range lampsFixture {
		if sum := sha256.Sum256(fixtureBytes(t, name)); hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s: sha256 %x, want %s", name, sum, want)
		}
	}
}

// The draft's own signature verifies: a third party's bytes, so this holds the
// composite to the standard and not only to another Macula stack.
func TestTheLAMPSDraftVectorVerifies(t *testing.T) {
	message, public, signature := fixtureBytes(t, "m.bin"), fixtureBytes(t, "pk.bin"), fixtureBytes(t, "s.bin")
	if !Verify(message, signature, public, profile.PQHybrid) {
		t.Fatal("the LAMPS draft vector does not verify")
	}
}

// A composite whose RSA-PSS half lost its leading zero byte is refused, as macula
// refuses it, and by its length alone: its ML-DSA-87 half verifies (under the
// composite label as its context), its RSA-PSS half verifies once the zero byte
// is back, and the composite restored to 4627 + 512 bytes verifies.
func TestAZeroDroppedCompositeIsRefused(t *testing.T) {
	message := fixtureBytes(t, "m.bin")
	public := fixtureBytes(t, "pk.bin")
	signature := fixtureBytes(t, "zero_dropped_sig.bin")
	if len(public) != 3118 || len(signature) != mldsaSignatureSize+511 {
		t.Fatalf("key %d bytes and signature %d bytes, want 3118 and 4627 + 511", len(public), len(signature))
	}
	rsaPublic, err := x509.ParsePKCS1PublicKey(public[mldsaPublicKeySize:])
	if err != nil {
		t.Fatalf("the RSA public key: %v", err)
	}
	representative := compositeRepresentative(message)
	digest := sha512.Sum384(representative)
	restoredHalf := append([]byte{0}, signature[mldsaSignatureSize:]...)
	restored := append(bytes.Clone(signature[:mldsaSignatureSize]), restoredHalf...)

	mlPublic, err := mldsa.NewPublicKey(mldsa.MLDSA87(), public[:mldsaPublicKeySize])
	if err != nil {
		t.Fatalf("the ML-DSA-87 public key: %v", err)
	}
	if err := mldsa.Verify(mlPublic, representative, signature[:mldsaSignatureSize], &mldsa.Options{Context: compositeLabel}); err != nil {
		t.Errorf("the ML-DSA-87 half under the composite label: %v", err)
	}
	if err := rsa.VerifyPSS(rsaPublic, crypto.SHA384, digest[:], restoredHalf, pssOptions); err != nil {
		t.Errorf("the RSA-PSS half with its zero byte restored: %v, want it verified", err)
	}
	if !Verify(message, restored, public, profile.PQHybrid) {
		t.Error("the composite with its zero byte restored does not verify")
	}
	if Verify(message, signature, public, profile.PQHybrid) {
		t.Error("the composite without its zero byte verifies")
	}
}
