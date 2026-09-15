package identity

import (
	"errors"
	"testing"
)

// A NodeKey that holds no key, such as the zero value, refuses to sign and has
// no public key, and never panics.
func TestAnEmptyNodeKeyRefusesToSignWithoutPanicking(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an empty node key panicked: %v", r)
		}
	}()
	var empty NodeKey
	if _, err := empty.Sign([]byte("a message")); !errors.Is(err, ErrEmptyNodeKey) {
		t.Errorf("Sign = %v, want ErrEmptyNodeKey", err)
	}
	if public := empty.PublicKey(); public != nil {
		t.Errorf("PublicKey holds %d bytes, want none", len(public))
	}
	if _, err := empty.NodeID(); !errors.Is(err, ErrNotAnIdentityKey) {
		t.Errorf("NodeID = %v, want ErrNotAnIdentityKey", err)
	}
}
