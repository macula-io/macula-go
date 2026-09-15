//go:build unix

package identity

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
)

// loadWithin is LoadKey's error for path, and fails the test when LoadKey has
// not returned within five seconds, as when it waits for a FIFO's writer.
func loadWithin(t *testing.T, path string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := LoadKey(path, PurposeIdentity, profile.PQPure)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		releaseFIFOReader(path)
		t.Fatalf("LoadKey(%s) did not return within 5 s", filepath.Base(path))
		return nil
	}
}

// releaseFIFOReader opens path for writing and closes it, so a reader waiting
// on a FIFO there returns.
func releaseFIFOReader(path string) {
	if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
		_ = f.Close()
	}
}

// countedOpens counts LoadKey's opens for the rest of the test.
func countedOpens(t *testing.T) *int {
	t.Helper()
	opens := 0
	open := openKeyFile
	openKeyFile = func(name string) (*os.File, error) {
		opens++
		return open(name)
	}
	t.Cleanup(func() { openKeyFile = open })
	return &opens
}

// LoadKey refuses a path that names anything but a regular file, through a
// symlink too, before it opens the path, so it never waits on a FIFO.
func TestLoadRefusesAPathThatIsNotARegularFileBeforeOpeningIt(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo.key")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	directory := filepath.Join(dir, "directory.key")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	device := filepath.Join(dir, "device.key")
	if err := os.Symlink(os.DevNull, device); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	paths := map[string]string{
		"a FIFO":                          fifo,
		"a directory":                     directory,
		"a symlink to a character device": device,
	}
	for name, path := range paths {
		t.Run(name, func(t *testing.T) {
			opens := countedOpens(t)
			if err := loadWithin(t, path); !errors.Is(err, ErrKeyFileNotRegular) {
				t.Errorf("LoadKey = %v, want ErrKeyFileNotRegular", err)
			}
			if *opens != 0 {
				t.Errorf("LoadKey opened the path %d times, want it refused before any open", *opens)
			}
		})
	}
}

// A path that becomes a FIFO between LoadKey's check and its open is refused on
// the open handle, without waiting for a writer.
func TestLoadRefusesAPathThatBecomesAFIFOAfterItsCheck(t *testing.T) {
	path := savedKeyFile(t, sharedKey(t, pureIdentityKey))
	open := openKeyFile
	openKeyFile = func(name string) (*os.File, error) {
		if err := os.Remove(name); err != nil {
			return nil, err
		}
		if err := syscall.Mkfifo(name, 0o600); err != nil {
			return nil, err
		}
		return open(name)
	}
	t.Cleanup(func() { openKeyFile = open })
	if err := loadWithin(t, path); !errors.Is(err, ErrKeyFileNotRegular) {
		t.Errorf("LoadKey = %v, want ErrKeyFileNotRegular", err)
	}
}

// LoadKey refuses a key file whose owner is not the effective user.
func TestLoadRefusesAKeyFileAnotherUserOwns(t *testing.T) {
	path := savedKeyFile(t, sharedKey(t, pureIdentityKey))
	euid := effectiveUID
	effectiveUID = func() int { return os.Geteuid() + 1 }
	t.Cleanup(func() { effectiveUID = euid })
	if _, err := LoadKey(path, PurposeIdentity, profile.PQPure); !errors.Is(err, ErrKeyFileOwner) {
		t.Errorf("LoadKey = %v, want ErrKeyFileOwner", err)
	}
}

// LoadKey follows a symlink and checks the file it names, as macula does: a
// symlink to an owner-only key file loads, and one to a key file its group can
// read is refused.
func TestLoadFollowsASymlinkAndChecksTheFileItNames(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	wants := map[fs.FileMode]error{0o600: nil, 0o640: ErrKeyFilePermissions}
	for mode, want := range wants {
		target := savedKeyFile(t, key)
		if err := os.Chmod(target, mode); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		link := filepath.Join(t.TempDir(), "link.key")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := LoadKey(link, PurposeIdentity, profile.PQPure); !errors.Is(err, want) {
			t.Errorf("a symlink to a key file of mode %o: LoadKey = %v, want %v", mode, err, want)
		}
	}
}

// sysLessFileInfo is a regular owner-only file whose platform information is
// missing, so it names no owner.
type sysLessFileInfo struct{}

func (sysLessFileInfo) Name() string       { return "node.key" }
func (sysLessFileInfo) Size() int64        { return 0 }
func (sysLessFileInfo) Mode() fs.FileMode  { return 0o600 }
func (sysLessFileInfo) ModTime() time.Time { return time.Time{} }
func (sysLessFileInfo) IsDir() bool        { return false }
func (sysLessFileInfo) Sys() any           { return nil }

// On a platform with user ids, a file whose owner cannot be read is refused as
// another user's, never let through unchecked.
func TestAKeyFileWhoseOwnerCannotBeReadIsRefused(t *testing.T) {
	if err := ownerOnly(sysLessFileInfo{}); !errors.Is(err, ErrKeyFileOwner) {
		t.Fatalf("ownerOnly on a file without an owner = %v, want ErrKeyFileOwner", err)
	}
}

// assertOwnerOnlyKeyFile fails the test unless path itself, not a symlink, is a
// regular file of mode 600 that loads as key.
func assertOwnerOnlyKeyFile(t *testing.T, path string, key *NodeKey) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("lstat: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("the key file is %v, want a regular file of mode 600", info.Mode())
	}
	loaded, err := LoadKey(path, key.Purpose(), key.Profile())
	if err != nil || !bytes.Equal(loaded.PublicKey(), key.PublicKey()) {
		t.Errorf("LoadKey after Save: %v, want the saved key", err)
	}
}

// unchangedContents fails the test unless the file at path still holds want.
// It never prints what the file holds, which could be key bytes.
func unchangedContents(t *testing.T, what, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != want {
		t.Errorf("%s holds %d bytes after Save (%v), want its %d bytes unchanged", what, len(contents), err, len(want))
	}
}

// Save neither writes through nor reuses anything at path+".tmp": a symlink or
// a file others can read planted there is unchanged afterwards.
func TestSaveLeavesWhatIsPlantedAtTheTemporaryPathUnchanged(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	const planted = "left as it was"

	t.Run("a symlink", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.key")
		victim := filepath.Join(t.TempDir(), "victim")
		if err := os.WriteFile(victim, []byte(planted), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Symlink(victim, path+".tmp"); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if err := key.Save(path); err != nil {
			t.Fatalf("Save: %v", err)
		}
		unchangedContents(t, "the symlink's target", victim, planted)
		if target, err := os.Readlink(path + ".tmp"); err != nil || target != victim {
			t.Errorf("the planted symlink points at %q (%v) after Save, want it unchanged", target, err)
		}
		assertOwnerOnlyKeyFile(t, path, key)
	})

	t.Run("a file others can read", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "node.key")
		if err := os.WriteFile(path+".tmp", []byte(planted), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := os.Chmod(path+".tmp", 0o644); err != nil {
			t.Fatalf("chmod: %v", err)
		}
		if err := key.Save(path); err != nil {
			t.Fatalf("Save: %v", err)
		}
		info, err := os.Lstat(path + ".tmp")
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o644 {
			t.Fatalf("the planted file after Save: %v, %v; want it unchanged", info, err)
		}
		unchangedContents(t, "the planted file", path+".tmp", planted)
		assertOwnerOnlyKeyFile(t, path, key)
	})
}
