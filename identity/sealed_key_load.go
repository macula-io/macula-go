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

// LoadOption changes how LoadSealedKey reads a key file.
type LoadOption func(*loadSettings)

// loadSettings is what a caller's options add up to.
type loadSettings struct {
	kekFile  string
	expected *[32]byte
}

// WithKEKFile names the file the KEK is read from. Without it the KEK comes from
// KEKFileEnv; with neither, a sealed file is refused as not configured, because
// a KEK is never read from beside a key file by default.
func WithKEKFile(path string) LoadOption {
	return func(settings *loadSettings) { settings.kekFile = path }
}

// WithExpectedKeyID is the key the caller must get: a file holding any other is
// refused as ErrKeyIDMismatch, sealed or plaintext. A caller that must refuse
// another node's whole sealed file — the case the format cannot catch when two
// boxes share a KEK — is the caller that passes it.
func WithExpectedKeyID(id [32]byte) LoadOption {
	return func(settings *loadSettings) { settings.expected = &id }
}

// LoadSealedKey reads the key file at path and answers the checked key it holds,
// sealed or plaintext, under mode.
//
// The file is checked the way LoadKey checks one before it is read: a regular
// file a symlink may lead to, owned by the effective user, that its group and
// others cannot read, of at most 64 KiB. A mode this package does not know is
// refused before anything is read, so neither path can carry on with no opinion.
// A sealed file then needs a KEK, from WithKEKFile or KEKFileEnv, checked as
// KEKFromFile checks one; a plaintext one is refused in ModeSealedRequired.
//
// The key that comes out is checked the way LoadKey checks one: its halves held
// to its own purpose and profile, every public half derived from its private
// half, and a sign-and-verify round trip.
func LoadSealedKey(path string, mode KeyFileMode, opts ...LoadOption) (SealedKey, error) {
	if mode != ModeAccept && mode != ModeSealedRequired {
		return SealedKey{}, fmt.Errorf("%w: %q", ErrUnknownKeyFileMode, mode)
	}
	var settings loadSettings
	for _, opt := range opts {
		opt(&settings)
	}
	contents, err := readKeyFile(path)
	if err != nil {
		return SealedKey{}, err
	}
	key, err := loadedKeyFile(contents, &settings, path, mode)
	if err != nil {
		return SealedKey{}, err
	}
	return expectedKey(settings.expected, key)
}

// loadedKeyFile is the key in contents, sealed or plaintext, under mode. The KEK
// is read only for a sealed file: a plaintext one under ModeAccept needs none,
// and asking for one there would refuse a load that is allowed.
func loadedKeyFile(contents []byte, settings *loadSettings, keyPath string, mode KeyFileMode) (SealedKey, error) {
	sealed := bytes.HasPrefix(contents, []byte(sealedKeyMagic))
	if !sealed && mode == ModeSealedRequired {
		return SealedKey{}, ErrPlaintextKeyRefused
	}
	kek, err := openableKEK(sealed, settings.kekFile, keyPath)
	if err != nil {
		return SealedKey{}, err
	}
	if sealed {
		return UnsealKeyFile(contents, kek)
	}
	return plaintextKey(contents)
}

// openableKEK is the KEK a sealed file needs, and nothing at all for a plaintext
// one.
func openableKEK(sealed bool, kekFile, keyPath string) ([]byte, error) {
	if !sealed {
		return nil, nil
	}
	return KEKFromFile(kekFile, keyPath)
}

// plaintextKey is the checked key a plaintext file holds.
func plaintextKey(contents []byte) (SealedKey, error) {
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

// expectedKey refuses a key other than the one the caller named, when it named
// one.
func expectedKey(expected *[32]byte, key SealedKey) (SealedKey, error) {
	if expected == nil || key.Key.KeyID() == *expected {
		return key, nil
	}
	return SealedKey{}, fmt.Errorf("%w: expected %x, the file holds %x", ErrKeyIDMismatch, *expected, key.Key.KeyID())
}
