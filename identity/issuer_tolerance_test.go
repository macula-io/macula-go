package identity

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// A clock stepped back by less than a verifier's 5 minutes of tolerance keeps
// the current CONNECT key, since its binding and statement still verify at that
// time. A step further back rotates it.
func TestAClockSteppedBackWithinTheToleranceKeepsTheConnectKey(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	first := currentMaterial(t, issuer)

	within := issuerT0 - 4*minuteMs
	clock.set(within)
	material := currentMaterial(t, issuer)
	if !bytes.Equal(material.Key.PublicKey(), first.Key.PublicKey()) {
		t.Fatal("a clock 4 minutes back rotated the CONNECT key, want it kept")
	}
	if _, err := VerifyConnectBinding(material.Binding, identity.PublicKey(), profile.PQPure, material.Key.PublicKey(), within); err != nil {
		t.Fatalf("the kept CONNECT binding 4 minutes back: %v", err)
	}
	if _, err := VerifyStatus(material.Status, material.Binding, identity.PublicKey(), profile.PQPure, within); err != nil {
		t.Fatalf("the kept statement 4 minutes back: %v", err)
	}

	beyond := issuerT0 - 6*minuteMs
	clock.set(beyond)
	material = currentMaterial(t, issuer)
	if bytes.Equal(material.Key.PublicKey(), first.Key.PublicKey()) {
		t.Fatal("a clock 6 minutes back kept the CONNECT key, want it rotated")
	}
	checkStatementAt(t, material.Status, material.Binding, identity, beyond)
}
