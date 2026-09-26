//go:build !windows

package identity

import (
	"io/fs"
	"os"
)

// Where a file's permissions are mode bits, a key file is readable by its
// owner only when its mode is 600 (or 400), and it must be the effective
// user's.

// restrictKeyFile makes f readable and writable by its owner only.
func restrictKeyFile(f *os.File) error { return f.Chmod(0o600) }

// ownerOnlyFile refuses an opened key file that is not the effective user's
// or that its group or others can read.
func ownerOnlyFile(_ *os.File, info fs.FileInfo) error { return ownerOnly(info) }

// ownerOnly refuses an opened key file that is not a regular file, that is not
// the effective user's, or that its group or others can read.
func ownerOnly(info fs.FileInfo) error {
	if !info.Mode().IsRegular() {
		return ErrKeyFileNotRegular
	}
	if !ownedByEffectiveUser(info) {
		return ErrKeyFileOwner
	}
	if info.Mode().Perm()&0o077 != 0 {
		return ErrKeyFilePermissions
	}
	return nil
}
