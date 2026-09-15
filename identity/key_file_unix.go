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

// fileOwner is the user id that owns the file info describes.
func fileOwner(info fs.FileInfo) (int, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int(stat.Uid), true
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
