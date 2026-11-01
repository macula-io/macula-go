package identity

import (
	"fmt"
	"io"
	"os"
)

// KEKFileEnv names the environment variable a deployment may name a KEK file
// in, as macula's MACULA_KEY_KEK_FILE does. A caller that passes WithKEKFile
// takes precedence over it.
const KEKFileEnv = "MACULA_KEY_KEK_FILE"

// sameDeviceOf decides whether the KEK and the key file sit on one filesystem,
// which is what a KEK beside the key on a single volume looks like. A test
// replaces it to hold both arms of the check without depending on where its
// files happen to be.
var sameDeviceOf = sameDevice

// KEKFromFile reads the key-encryption key at kekPath, or at KEKFileEnv when
// kekPath is empty, and checks it before it is used:
//
//   - it must be named at all: a KEK is never read from beside the key file by
//     default, because a whole-disk copy would carry both (ErrKEKNotConfigured);
//   - it must open, and the file system's own reason is what an operator needs,
//     so that error is wrapped and returned (not replaced);
//   - it must be a regular file (ErrKeyFileNotRegular), decided before the open
//     so a FIFO is named as one instead of waited on;
//   - another user must not own it, and nobody else must be able to read it
//     (ErrKeyFileOwner, ErrKeyFilePermissions), by the same check a key file
//     gets on this platform;
//   - it must not be on keyPath's own filesystem (ErrKEKSameFilesystem), the
//     volume serial where a platform has those and the device where it has
//     that: on a single-volume box without a TPM it is the difference between
//     a stolen disk image holding ciphertext and holding both halves;
//   - it must be 32 bytes (ErrKEKSize).
func KEKFromFile(kekPath, keyPath string) ([]byte, error) {
	path := kekPath
	if path == "" {
		path = os.Getenv(KEKFileEnv)
	}
	if path == "" {
		return nil, ErrKEKNotConfigured
	}
	f, info, err := openedKEKFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if err := kekOwnFilesystem(f, info, keyPath); err != nil {
		return nil, err
	}
	return readKEK(f, path)
}

// openedKEKFile opens path once it names a regular file, and checks that the
// opened file is the effective user's own and that nobody else can read it:
// mode bits where a file has them, its DACL where it has those instead.
//
// The stat before the open is not the check — the opened file's own info is.
// It is there so that a path which is, or has become, a FIFO is refused as what
// it is instead of blocking the open; where the platform can, the open itself
// does not wait either.
func openedKEKFile(path string) (*os.File, os.FileInfo, error) {
	statted, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: read the KEK: %w", err)
	}
	if !statted.Mode().IsRegular() {
		return nil, nil, ErrKeyFileNotRegular
	}
	f, err := openKeyFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: read the KEK: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("identity: read the KEK: %w", err)
	}
	if err := ownerOnlyFile(f, info); err != nil {
		f.Close()
		return nil, nil, err
	}
	return f, info, nil
}

// kekOwnFilesystem refuses a KEK on the key file's own filesystem. A key file
// that cannot be stat'ed is the caller's own refusal to make later, not this
// one's: the check passes when there is nothing to compare against.
func kekOwnFilesystem(kek *os.File, kekInfo os.FileInfo, keyPath string) error {
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		return nil
	}
	if sameDeviceOf(kek, keyPath, kekInfo, keyInfo) {
		return ErrKEKSameFilesystem
	}
	return nil
}

// readKEK is the KEK in f, refused unless it is 32 bytes.
func readKEK(f *os.File, path string) ([]byte, error) {
	kek, err := io.ReadAll(io.LimitReader(f, kekBytes+1))
	if err != nil {
		return nil, fmt.Errorf("identity: read the KEK: %w", err)
	}
	if len(kek) != kekBytes {
		return nil, fmt.Errorf("%w: %s holds %d bytes", ErrKEKSize, path, len(kek))
	}
	return kek, nil
}
