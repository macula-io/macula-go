package frame_test

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// Signing a frame returns a new frame and changes no frame signed before it:
// not when the same unsigned frame is signed again by someone else, and not
// when an already signed frame is signed again.
func TestSigningAFrameLeavesEveryFrameSignedBeforeIntact(t *testing.T) {
	first, second := mustIdentity(t), mustIdentity(t)
	unsigned := frame.Call(frame.NewCallSpec(make([]byte, 16), "p", make([]byte, 32), cbor.Null(), time.Now().UnixMilli(), first.NodeID()))

	byFirst := frame.Sign(unsigned, first)
	bySecond := frame.Sign(unsigned, second)
	if err := frame.Verify(byFirst, first.NodeID()); err != nil {
		t.Fatalf("the frame signed first no longer verifies after the same unsigned frame was signed again: %v", err)
	}
	if err := frame.Verify(bySecond, second.NodeID()); err != nil {
		t.Fatalf("the frame signed second doesn't verify: %v", err)
	}

	_ = frame.Sign(byFirst, second)
	if err := frame.Verify(byFirst, first.NodeID()); err != nil {
		t.Fatalf("a signed frame no longer verifies after it was signed again: %v", err)
	}
	if _, signed := unsigned.Get("signature"); signed {
		t.Fatal("the unsigned frame gained a signature")
	}
}

func mustIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}
