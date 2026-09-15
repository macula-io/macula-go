//go:build !unix

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

// syncDir does nothing: these platforms cannot sync a directory's entries.
func syncDir(string) error {
	return nil
}
