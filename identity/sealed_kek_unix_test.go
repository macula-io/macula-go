//go:build !windows

package identity

import (
	"errors"
	"testing"
)

// refuseAKEKOthersCanRead writes a KEK file whose group and others may read it
// and holds KEKFromFile to refusing it. Where permissions are mode bits, 0644
// is exactly that file.
func refuseAKEKOthersCanRead(t *testing.T, kek []byte, keyPath string) {
	t.Helper()
	path := writtenKEKFileAt(t, kek, 0o644)
	if _, err := KEKFromFile(path, keyPath); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatalf("%v, want %v", err, ErrKeyFilePermissions)
	}
}
