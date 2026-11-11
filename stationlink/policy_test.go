package stationlink

import (
	"testing"

	"github.com/macula-io/macula-go/frame"
)

// No policy is not a policy (macula-go#57, #60): a serve names who may call,
// and the enforcement point refuses a request whose procedure has none, so the
// property "nothing is served without a policy named at advertise" holds here
// whatever path built the offer.
func TestNoPolicyIsNotAPolicy(t *testing.T) {
	if validPolicy(nil) {
		t.Error("validPolicy(nil) is true, want false: no policy names nobody")
	}
	if code := (&Link{}).authorize(nil, frame.VerifiedRequest{}); code != codeUnauthorized {
		t.Errorf("a request under no policy: %q, want %q", code, codeUnauthorized)
	}
}
