//go:build windows

package identity

import (
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// refuseAKEKOthersCanRead writes a KEK file and grants Everyone read access to
// it, and holds KEKFromFile to refusing it. Windows permissions are a DACL, not
// mode bits, so a wide mode on its own widens nothing: the grant is what makes
// the file one somebody else can read.
func refuseAKEKOthersCanRead(t *testing.T, kek []byte, keyPath string) {
	t.Helper()
	path := writtenKEKFileAt(t, kek, 0o600)
	grant(t, path, windows.WinWorldSid, windows.FILE_READ_DATA)
	if _, err := KEKFromFile(path, keyPath); !errors.Is(err, ErrKeyFilePermissions) {
		t.Fatalf("%v, want %v", err, ErrKeyFilePermissions)
	}
}
