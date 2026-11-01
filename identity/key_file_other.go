//go:build !unix && !windows

package identity

import (
	"io/fs"
	"os"
)

// keyFileOpenFlags open a key file for reading.
const keyFileOpenFlags = os.O_RDONLY

// ownedByEffectiveUser reports true: these platforms have no user ids to
// compare.
func ownedByEffectiveUser(fs.FileInfo) bool {
	return true
}

// sameDevice reports false: these platforms have no device to compare, so the
// KEK check that depends on one passes rather than guessing.
func sameDevice(fs.FileInfo, fs.FileInfo) bool {
	return false
}

// syncDir does nothing: these platforms cannot sync a directory's entries.
func syncDir(string) error {
	return nil
}
