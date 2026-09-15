//go:build unix

package identity

import (
	"io/fs"
	"os"
	"syscall"
)

// keyFileOpenFlags open a key file for reading without waiting, should its path
// have become a FIFO since LoadKey checked it.
const keyFileOpenFlags = os.O_RDONLY | syscall.O_NONBLOCK

// ownedByEffectiveUser reports whether the file info describes belongs to the
// effective user. Information that names no owner belongs to no one here, so
// the check refuses it rather than passing it.
func ownedByEffectiveUser(info fs.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == effectiveUID()
}

// syncDir flushes dir's entries to storage, so a rename into it survives a
// crash.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	if closeErr := d.Close(); err == nil {
		err = closeErr
	}
	return err
}
