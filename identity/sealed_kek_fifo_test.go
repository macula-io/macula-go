//go:build unix

package identity

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestAKEKThatIsNotARegularFileIsRefused holds the check that runs before the
// open: a FIFO named as a KEK is refused as what it is rather than waited on.
// A plain open of a FIFO blocks until a writer arrives, so without the check a
// wrong deployment path is a boot that never finishes and never says why.
func TestAKEKThatIsNotARegularFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "node.key")
	if err := os.WriteFile(keyPath, []byte("a key file"), 0o600); err != nil {
		t.Fatalf("write the key file: %v", err)
	}
	fifo := filepath.Join(dir, "kek")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("make the FIFO: %v", err)
	}
	if _, err := KEKFromFile(fifo, keyPath); !errors.Is(err, ErrKeyFileNotRegular) {
		t.Fatalf("%v, want %v", err, ErrKeyFileNotRegular)
	}
}
