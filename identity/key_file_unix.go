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

// sameDevice reports whether the open KEK file and the key file at keyPath are
// on one filesystem, which is what a KEK beside the key on a single volume
// looks like: one st_dev, one disk.
func sameDevice(_ *os.File, _ string, a, b fs.FileInfo) bool {
	one, ok := a.Sys().(*syscall.Stat_t)
	other, okOther := b.Sys().(*syscall.Stat_t)
	return ok && okOther && one.Dev == other.Dev
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
