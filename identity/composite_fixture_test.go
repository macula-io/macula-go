package identity

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// zeroDroppedFixture is the zero-dropped composite from macula's
// test/fixtures/composite_ml_dsa_87_ps384 at merge-11.0.0 bdbd6720, by the
// sha256 macula records for each file: a pq_hybrid composite over message.bin
// whose RSA-PSS half had its leading zero byte dropped, 4627 + 511 bytes.
// macula_node_keys:verify/4 refuses the same bytes
// (cross_stack_zero_dropped_composite_is_refused_test).
var zeroDroppedFixture = map[string]string{
	"message.bin":                    "0bd6435c67f59022b2c9c09b47aaf9cc5e21afdc1bac1269c43f094968a8f313",
	"zero_dropped_composite_pub.bin": "2a088f4f99874258d8f6206fa605ff17645fd191a7f9c9216b2ee0da3b2dbc78",
	"zero_dropped_composite_sig.bin": "87bac541d243135bc330ce21173ff90a27c94dd41c0f3ecd96c6014d0067e6c0",
}

// A composite whose RSA-PSS half lost its leading zero byte is refused, as macula
// refuses it, and by its length alone: its ML-DSA-87 half verifies, its RSA-PSS
// half verifies once the zero byte is back, and the composite restored to 4627 +
// 512 bytes verifies.
func TestAZeroDroppedCompositeIsRefused(t *testing.T) {
	for name, want := range zeroDroppedFixture {
		if sum := sha256.Sum256(fixtureBytes(t, name)); hex.EncodeToString(sum[:]) != want {
			t.Fatalf("%s: sha256 %x, want macula's %s", name, sum, want)
		}
	}
	message := fixtureBytes(t, "message.bin")
	public := fixtureBytes(t, "zero_dropped_composite_pub.bin")
	signature := fixtureBytes(t, "zero_dropped_composite_sig.bin")
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

	if !verifyMLDSA(public[:mldsaPublicKeySize], representative, signature[:mldsaSignatureSize]) {
		t.Error("the ML-DSA-87 half does not verify")
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
