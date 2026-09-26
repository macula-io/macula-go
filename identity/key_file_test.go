package identity

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// seedKeyFileMagic opens every key file macula-go writes. macula's own files,
// which hold the expanded ML-DSA-87 key, open with "macula-node-key-v1".
const seedKeyFileMagic = "macula-node-key-seed-v1\x00"

// keyFileComponent is one half of a key as a key file lays it out: its
// algorithm tag (1 for an ML-DSA-87 seed, 2 for an RSA-PSS PKCS #1 key), its
// public key and its private key.
type keyFileComponent struct {
	tag     byte
	public  []byte
	private []byte
}

// keyFileBytes is a key file laid out by hand: the magic, the purpose tag
// (1 identity, 2 connect), the profile tag (1 pq_pure, 2 pq_hybrid), the
// component count, and each component with its public and private keys
// length-prefixed in four big-endian bytes.
func keyFileBytes(purposeTag, profileTag byte, components ...keyFileComponent) []byte {
	out := append([]byte(seedKeyFileMagic), purposeTag, profileTag, byte(len(components)))
	for _, c := range components {
		out = append(out, c.tag)
		out = binary.BigEndian.AppendUint32(out, uint32(len(c.public)))
		out = append(out, c.public...)
		out = binary.BigEndian.AppendUint32(out, uint32(len(c.private)))
		out = append(out, c.private...)
	}
	return out
}

// withByteAt is b with the byte at offset set to value.
func withByteAt(b []byte, offset int, value byte) []byte {
	c := bytes.Clone(b)
	c[offset] = value
	return c
}

// writtenKeyFile writes contents, readable by its owner only, to a new
// directory and returns the file's path.
func writtenKeyFile(t *testing.T, contents []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.key")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("write key file: %v", err)
	}
	if err := writeRestricted(f, contents); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

// savedKeyFile saves key in a new directory and returns the file's path.
func savedKeyFile(t *testing.T, key *NodeKey) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "node.key")
	if err := key.Save(path); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return path
}

func mldsaComponent(key *NodeKey) keyFileComponent {
	return keyFileComponent{tag: 1, public: key.PublicKey()[:mldsaPublicKeySize], private: key.mldsa.Bytes()}
}

func rsaComponent(key *rsa.PrivateKey) keyFileComponent {
	return keyFileComponent{tag: 2, public: x509.MarshalPKCS1PublicKey(&key.PublicKey), private: x509.MarshalPKCS1PrivateKey(key)}
}

func TestKeysSurviveSaveAndLoad(t *testing.T) {
	connect, err := GenerateKey(PurposeConnect, profile.PQPure)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	for _, key := range []*NodeKey{sharedKey(t, pureIdentityKey), connect, sharedKey(t, hybridIdentityKey)} {
		loaded, err := LoadKey(savedKeyFile(t, key), key.Purpose(), key.Profile())
		if err != nil {
			t.Fatalf("%s: LoadKey: %v", key, err)
		}
		if !bytes.Equal(loaded.PublicKey(), key.PublicKey()) || loaded.Purpose() != key.Purpose() || loaded.Profile() != key.Profile() {
			t.Errorf("%s: loaded as %s", key, loaded)
		}
		message := []byte("signed after a reload")
		signature, err := loaded.Sign(message)
		if err != nil || !Verify(message, signature, key.PublicKey(), key.Profile()) {
			t.Errorf("%s: the loaded key does not sign for the saved one: %v", key, err)
		}
	}
}

// A key file holds the seed form: the 32-byte ML-DSA-87 seed, and in pq_hybrid
// the PKCS #1 RSA key, each beside its public key.
func TestSaveWritesTheSeedFormLayout(t *testing.T) {
	pure := sharedKey(t, pureIdentityKey)
	hybrid := sharedKey(t, hybridIdentityKey)
	cases := []struct {
		key  *NodeKey
		want []byte
	}{
		{pure, keyFileBytes(1, 1, mldsaComponent(pure))},
		{hybrid, keyFileBytes(1, 2, mldsaComponent(hybrid), rsaComponent(hybrid.rsa))},
	}
	for _, c := range cases {
		path := savedKeyFile(t, c.key)
		saved, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(saved, c.want) {
			t.Errorf("%s: the saved file does not have the seed-form layout", c.key)
		}
		entries, err := os.ReadDir(filepath.Dir(path))
		if err != nil || len(entries) != 1 {
			t.Errorf("%s: the directory holds %d entries after Save, want only the key file", c.key, len(entries))
		}
	}
}

func TestLoadingAMissingKeyFileSaysItDoesNotExist(t *testing.T) {
	_, err := LoadKey(filepath.Join(t.TempDir(), "absent.key"), PurposeIdentity, profile.PQPure)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadKey = %v, want fs.ErrNotExist", err)
	}
}

func TestLoadRefusesAKeyItCannotTrust(t *testing.T) {
	pure := sharedKey(t, pureIdentityKey)
	hybrid := sharedKey(t, hybridIdentityKey)
	small, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate RSA-3072: %v", err)
	}
	pureHalf := mldsaComponent(pure)
	hybridHalf := mldsaComponent(hybrid)
	rsaHalf := rsaComponent(hybrid.rsa)
	otherModulus := new(big.Int).Add(hybrid.rsa.N, big.NewInt(2))
	countAt := len(seedKeyFileMagic) + 2

	cases := []struct {
		name    string
		file    []byte
		purpose Purpose
		p       profile.Profile
		want    error
	}{
		{"a stored ML-DSA-87 public key that differs from the derived one",
			keyFileBytes(1, 1, keyFileComponent{1, flippedAt(pureHalf.public, 100), pureHalf.private}),
			PurposeIdentity, profile.PQPure, ErrPublicKeyMismatch},
		{"a changed seed",
			keyFileBytes(1, 1, keyFileComponent{1, pureHalf.public, flippedAt(pureHalf.private, 0)}),
			PurposeIdentity, profile.PQPure, ErrPublicKeyMismatch},
		{"a seed of another length",
			keyFileBytes(1, 1, keyFileComponent{1, pureHalf.public, pureHalf.private[:31]}),
			PurposeIdentity, profile.PQPure, ErrPrivateKeyInvalid},
		{"a key saved for another purpose", keyFileBytes(2, 1, pureHalf), PurposeIdentity, profile.PQPure, ErrWrongPurpose},
		{"a key saved for another profile", keyFileBytes(1, 1, pureHalf), PurposeIdentity, profile.PQHybrid, ErrWrongProfile},
		{"a hybrid key labelled pq_pure", keyFileBytes(1, 1, hybridHalf, rsaHalf), PurposeIdentity, profile.PQPure, ErrWrongAlgorithms},
		{"a pq_hybrid key without its RSA-PSS half", keyFileBytes(1, 2, hybridHalf), PurposeIdentity, profile.PQHybrid, ErrWrongAlgorithms},
		{"a stored RSA public key that differs from the derived one",
			keyFileBytes(1, 2, hybridHalf, keyFileComponent{2, rsaPublicDER(otherModulus, 65537), rsaHalf.private}),
			PurposeIdentity, profile.PQHybrid, ErrPublicKeyMismatch},
		{"an RSA private key that does not parse",
			keyFileBytes(1, 2, hybridHalf, keyFileComponent{2, rsaHalf.public, flippedAt(rsaHalf.private, 0)}),
			PurposeIdentity, profile.PQHybrid, ErrPrivateKeyInvalid},
		{"an RSA-3072 half", keyFileBytes(1, 2, hybridHalf, rsaComponent(small)), PurposeIdentity, profile.PQHybrid, ErrWrongKeySize},
		{"bytes after the last component", append(keyFileBytes(1, 1, pureHalf), 0), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"a truncated file", keyFileBytes(1, 1, pureHalf)[:1000], PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"a component count that disagrees", withByteAt(keyFileBytes(1, 1, pureHalf), countAt, 2), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"an unknown purpose tag", keyFileBytes(9, 1, pureHalf), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"an unknown profile tag", keyFileBytes(1, 9, pureHalf), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"an unknown algorithm tag", keyFileBytes(1, 1, keyFileComponent{9, pureHalf.public, pureHalf.private}), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"an Ed25519 seed file", make([]byte, 32), PurposeIdentity, profile.PQPure, ErrBadKeyFile},
		{"a key file in macula's expanded form",
			append([]byte("macula-node-key-v1\x00"), keyFileBytes(1, 1, pureHalf)[len(seedKeyFileMagic):]...),
			PurposeIdentity, profile.PQPure, ErrBadKeyFile},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := LoadKey(writtenKeyFile(t, c.file), c.purpose, c.p); !errors.Is(err, c.want) {
				t.Errorf("LoadKey = %v, want %v", err, c.want)
			}
		})
	}
}

// LoadKey reads at most maxKeyFileBytes: a file one byte longer is refused as
// too large, and a file of exactly that length is read and judged by what it
// holds.
func TestLoadRefusesAKeyFileLongerThanTheCap(t *testing.T) {
	valid := keyFileBytes(1, 1, mldsaComponent(sharedKey(t, pureIdentityKey)))
	atCap := append(bytes.Clone(valid), make([]byte, maxKeyFileBytes-len(valid))...)
	if _, err := LoadKey(writtenKeyFile(t, atCap), PurposeIdentity, profile.PQPure); !errors.Is(err, ErrBadKeyFile) {
		t.Errorf("a file of %d bytes: LoadKey = %v, want ErrBadKeyFile", len(atCap), err)
	}
	overCap := append(atCap, 0)
	if _, err := LoadKey(writtenKeyFile(t, overCap), PurposeIdentity, profile.PQPure); !errors.Is(err, ErrKeyFileTooLarge) {
		t.Errorf("a file of %d bytes: LoadKey = %v, want ErrKeyFileTooLarge", len(overCap), err)
	}
}
