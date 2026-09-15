//go:build !unix

package identity

import (
	"io/fs"
	"os"
)

// keyFileOpenFlags open a key file for reading.
const keyFileOpenFlags = os.O_RDONLY

// fileOwner reports no owner: these platforms have no user ids to compare.
func fileOwner(fs.FileInfo) (int, bool) {
	return 0, false
}

// syncDir does nothing: these platforms cannot sync a directory's entries.
func syncDir(string) error {
	return nil
}
