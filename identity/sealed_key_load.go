package identity

import (
	"bytes"
	"fmt"
)

// KeyFileMode is how a key file load treats a plaintext file. It is the Go
// half of macula's key_file_mode setting, and it exists for the same reason: a
// box that has been sealed must fail on a plaintext key file rather than carry
// on quietly with one.
type KeyFileMode string

const (
	// ModeAccept loads a plaintext key file as it always did.
	ModeAccept KeyFileMode = "accept"
	// ModeSealedRequired refuses a plaintext key file. A sealed one loads
	// either way: the mode is about what a copy of the file is worth.
	ModeSealedRequired KeyFileMode = "sealed_required"
)

// LoadSealedKey reads the key file at path and answers the key it holds, sealed
// or plaintext, under mode. A sealed file is opened with kek; a plaintext one
// loads under ModeAccept and is refused under ModeSealedRequired.
//
// The file is checked the way LoadKey checks one before it is read: a regular
// file a symlink may lead to, owned by the effective user, that its group and
// others cannot read, of at most 64 KiB. A mode this package does not know is
// refused before anything is read, so neither path can carry on with no opinion.
func LoadSealedKey(path string, kek []byte, mode KeyFileMode) (SealedKey, error) {
	if mode != ModeAccept && mode != ModeSealedRequired {
		return SealedKey{}, fmt.Errorf("%w: %q", ErrUnknownKeyFileMode, mode)
	}
	contents, err := readKeyFile(path)
	if err != nil {
		return SealedKey{}, err
	}
	return loadedKeyFile(contents, kek, mode)
}

// loadedKeyFile is the key in contents, sealed or plaintext, under mode. Both
// forms are checked the same way once their bytes are in hand: the header's
// claims are held to the key for a sealed file, and the key is held to its own
// profile with a sign-and-verify round trip either way.
func loadedKeyFile(contents, kek []byte, mode KeyFileMode) (SealedKey, error) {
	if bytes.HasPrefix(contents, []byte(sealedKeyMagic)) {
		return UnsealKeyFile(contents, kek)
	}
	if mode == ModeSealedRequired {
		return SealedKey{}, ErrPlaintextKeyRefused
	}
	file, err := parseSealedPayload(contents)
	if err != nil {
		return SealedKey{}, err
	}
	key, err := checkedFileKey(file)
	if err != nil {
		return SealedKey{}, err
	}
	return SealedKey{Key: key, KeyFile: contents}, nil
}
