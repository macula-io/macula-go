//go:build unix || windows

package identity

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestAKEKBesideTheKeyFileIsRefused holds the filesystem check with nothing
// replaced: a KEK written into the key file's own directory is on the key's own
// filesystem whatever that filesystem is, and is refused before it is read.
//
// The other test of this check replaces the answer so it can hold both arms
// wherever it runs; this one does not, so it is what fails if a platform's
// answer stops coming from the filesystem at all — the case a Windows build
// answered "different" for everything by saying it had nothing to compare.
func TestAKEKBesideTheKeyFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")
	if err := os.WriteFile(keyPath, []byte("a key file"), 0o600); err != nil {
		t.Fatalf("write the key file: %v", err)
	}
	kekPath := writtenKEKFileIn(t, dir, bytes.Repeat([]byte{0x2a}, kekBytes))
	if _, err := KEKFromFile(kekPath, keyPath); !errors.Is(err, ErrKEKSameFilesystem) {
		t.Fatalf("%v, want %v", err, ErrKEKSameFilesystem)
	}
}
