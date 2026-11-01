package identity

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// TestLoadSealedKeyExpectedKeyID holds the load to the key the caller must get.
// Without the option the reader can only catch a file whose header and content
// disagree; with it, a whole sealed file of another node's — the substitution
// two boxes sharing a KEK would otherwise accept — is refused by name.
func TestLoadSealedKeyExpectedKeyID(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	keyPath := writtenKeyFile(t, hexOf(t, v.Sealed))
	kekPath := writtenKEKFile(t, hexOf(t, v.KEK))
	withSameDevice(t, false)

	loaded, err := LoadSealedKey(keyPath, ModeSealedRequired, WithKEKFile(kekPath), WithExpectedKeyID(arrayOf(t, v.KeyID)))
	if err != nil {
		t.Fatalf("the key asked for is refused: %v", err)
	}
	if loaded.Key.KeyID() != arrayOf(t, v.KeyID) {
		t.Errorf("key id %x, want %s", loaded.Key.KeyID(), v.KeyID)
	}

	other := arrayOf(t, v.KeyID)
	other[0] ^= 0xff
	if _, err := LoadSealedKey(keyPath, ModeSealedRequired, WithKEKFile(kekPath), WithExpectedKeyID(other)); !errors.Is(err, ErrKeyIDMismatch) {
		t.Errorf("another key's id: %v, want %v", err, ErrKeyIDMismatch)
	}

	if _, err := LoadSealedKey(keyPath, ModeSealedRequired, WithKEKFile(kekPath)); err != nil {
		t.Errorf("no id asked for: %v", err)
	}

	plainPath := writtenKeyFile(t, hexOf(t, v.Plaintext))
	if _, err := LoadSealedKey(plainPath, ModeAccept, WithKEKFile(kekPath), WithExpectedKeyID(other)); !errors.Is(err, ErrKeyIDMismatch) {
		t.Errorf("a plaintext file of another key: %v, want %v", err, ErrKeyIDMismatch)
	}
}

// TestKEKFromFileRefusals holds a KEK file to the checks the design asks for
// before the KEK is used: it must be named at all, it must open, another user
// must not be able to read it, it must not sit on the key file's own
// filesystem, and it must be 32 bytes.
func TestKEKFromFileRefusals(t *testing.T) {
	kek := bytes.Repeat([]byte{0x2a}, kekBytes)
	keyPath := writtenKeyFile(t, []byte("a key file"))

	t.Run("not configured", func(t *testing.T) {
		t.Setenv(KEKFileEnv, "")
		if _, err := KEKFromFile("", keyPath); !errors.Is(err, ErrKEKNotConfigured) {
			t.Fatalf("%v, want %v", err, ErrKEKNotConfigured)
		}
	})

	t.Run("another user can read it", func(t *testing.T) {
		withSameDevice(t, false)
		refuseAKEKOthersCanRead(t, kek, keyPath)
	})

	t.Run("on the key file's own filesystem", func(t *testing.T) {
		withSameDevice(t, true)
		path := writtenKEKFile(t, kek)
		if _, err := KEKFromFile(path, keyPath); !errors.Is(err, ErrKEKSameFilesystem) {
			t.Fatalf("%v, want %v", err, ErrKEKSameFilesystem)
		}
	})

	t.Run("not 32 bytes", func(t *testing.T) {
		withSameDevice(t, false)
		path := writtenKEKFile(t, kek[:kekBytes-1])
		if _, err := KEKFromFile(path, keyPath); !errors.Is(err, ErrKEKSize) {
			t.Fatalf("%v, want %v", err, ErrKEKSize)
		}
	})

	t.Run("not a file", func(t *testing.T) {
		withSameDevice(t, false)
		missing := filepath.Join(t.TempDir(), "no-such-kek")
		_, err := KEKFromFile(missing, keyPath)
		if err == nil || errors.Is(err, ErrKEKNotConfigured) {
			t.Fatalf("%v, want the file system's own error", err)
		}
	})

	t.Run("the environment names it", func(t *testing.T) {
		withSameDevice(t, false)
		path := writtenKEKFile(t, kek)
		t.Setenv(KEKFileEnv, path)
		read, err := KEKFromFile("", keyPath)
		if err != nil {
			t.Fatalf("KEKFromFile from the environment: %v", err)
		}
		if !bytes.Equal(read, kek) {
			t.Error("the KEK read is not the one in the file")
		}
	})
}

// TestLoadSealedKeyNeedsAKEKFile holds the loader to the design's one source: a
// KEK comes from a file the deployment names, never from beside the key file by
// default, so a load with no KEK named is refused before anything is read.
func TestLoadSealedKeyNeedsAKEKFile(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	t.Setenv(KEKFileEnv, "")
	keyPath := writtenKeyFile(t, hexOf(t, v.Sealed))
	if _, err := LoadSealedKey(keyPath, ModeSealedRequired); !errors.Is(err, ErrKEKNotConfigured) {
		t.Fatalf("%v, want %v", err, ErrKEKNotConfigured)
	}
}

// TestLoadSealedKeyNamesAModeBeforeAKEK holds the order: a mode nobody knows is
// refused even when no KEK is configured, so an operator with both wrong is
// told about the one they can fix first.
func TestLoadSealedKeyNamesAModeBeforeAKEK(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	t.Setenv(KEKFileEnv, "")
	keyPath := writtenKeyFile(t, hexOf(t, v.Sealed))
	if _, err := LoadSealedKey(keyPath, "sealing"); !errors.Is(err, ErrUnknownKeyFileMode) {
		t.Fatalf("%v, want %v", err, ErrUnknownKeyFileMode)
	}
}

// writtenKEKFile writes a KEK file its owner alone can read, in a new directory.
func writtenKEKFile(t *testing.T, contents []byte) string {
	t.Helper()
	return writtenKEKFileAt(t, contents, 0o600)
}

func writtenKEKFileAt(t *testing.T, contents []byte, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "kek")
	if err := os.WriteFile(path, contents, mode); err != nil {
		t.Fatalf("write the KEK file: %v", err)
	}
	// WriteFile honours the umask; a test that asks for 0644 must get it.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod the KEK file: %v", err)
	}
	return path
}

// withSameDevice decides what the KEK's filesystem check answers, so a test can
// hold both of its arms without depending on where its temporary directory is.
func withSameDevice(t *testing.T, same bool) {
	t.Helper()
	original := sameDeviceOf
	sameDeviceOf = func(_, _ fs.FileInfo) bool { return same }
	t.Cleanup(func() { sameDeviceOf = original })
}

// TestLoadSealedKeyOnTheSDKsOwnKeyFileWithAKEKFile is the whole path a
// deployment walks: a key this package saved, sealed, and loaded back with a
// KEK file and the key id it expects.
func TestLoadSealedKeyOnTheSDKsOwnKeyFileWithAKEKFile(t *testing.T) {
	original, err := GenerateKey(PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext, err := os.ReadFile(savedKeyFile(t, original))
	if err != nil {
		t.Fatalf("read the saved key: %v", err)
	}
	kek := bytes.Repeat([]byte{0x2a}, kekBytes)
	sealed, err := SealKeyFile(plaintext, kek, bytes.Repeat([]byte{0x11}, nonceBytes))
	if err != nil {
		t.Fatalf("SealKeyFile: %v", err)
	}

	withSameDevice(t, false)
	loaded, err := LoadSealedKey(
		writtenKeyFile(t, sealed),
		ModeSealedRequired,
		WithKEKFile(writtenKEKFile(t, kek)),
		WithExpectedKeyID(original.KeyID()),
	)
	if err != nil {
		t.Fatalf("LoadSealedKey: %v", err)
	}
	checkSameKey(t, original, loaded, true)
}
