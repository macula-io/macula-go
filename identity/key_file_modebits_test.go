//go:build !windows

package identity

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// Where permissions are mode bits: a key file is saved as mode 600, and one
// its group or others can read is refused. Windows checks its DACL instead
// (key_file_windows_test.go).

func TestASavedKeyFileIsReadableByItsOwnerOnly(t *testing.T) {
	info, err := os.Stat(savedKeyFile(t, sharedKey(t, pureIdentityKey)))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("the key file's mode is %o, want 600", perm)
	}
}

func TestAKeyFileItsGroupOrOthersCanReadIsRefused(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	for _, mode := range []fs.FileMode{0o640, 0o604, 0o660, 0o606, 0o644} {
		path := savedKeyFile(t, key)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); !errors.Is(err, ErrKeyFilePermissions) {
			t.Errorf("mode %o: LoadKey = %v, want ErrKeyFilePermissions", mode, err)
		}
	}
	for _, mode := range []fs.FileMode{0o600, 0o400} {
		path := savedKeyFile(t, key)
		if err := os.Chmod(path, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); err != nil {
			t.Errorf("mode %o: LoadKey = %v, want it loaded", mode, err)
		}
	}
}
