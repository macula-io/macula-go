package identity

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/macula-io/macula-go/profile"
)

// keyFileMagic opens every key file this package writes. It holds the seed
// form of a key; macula's own key files hold the expanded ML-DSA-87 key and
// open with "macula-node-key-v1", so one is never taken for the other.
const keyFileMagic = "macula-node-key-seed-v1\x00"

// The refusals of LoadKey.
var (
	// ErrKeyFilePermissions is a key file its group or others can read.
	ErrKeyFilePermissions = errors.New("identity: the key file can be read by its group or others")
	// ErrBadKeyFile is a file that is not a key file in the seed form.
	ErrBadKeyFile = errors.New("identity: not a key file in the seed form")
	// ErrWrongPurpose is a key file that holds a key for another purpose.
	ErrWrongPurpose = errors.New("identity: the key file holds a key for another purpose")
	// ErrWrongProfile is a key file that holds a key for another profile.
	ErrWrongProfile = errors.New("identity: the key file holds a key for another profile")
	// ErrWrongAlgorithms is a key whose halves do not fit its purpose and
	// profile.
	ErrWrongAlgorithms = errors.New("identity: the key's halves do not fit its purpose and profile")
	// ErrWrongKeySize is an RSA-PSS half that is not a 4,096-bit key with
	// exponent 65537.
	ErrWrongKeySize = errors.New("identity: the RSA-PSS half is not a 4096-bit key with exponent 65537")
	// ErrPrivateKeyInvalid is a private key that does not decode.
	ErrPrivateKeyInvalid = errors.New("identity: the key file's private key is not valid")
	// ErrPublicKeyMismatch is a stored public key that differs from the one
	// its private key derives.
	ErrPublicKeyMismatch = errors.New("identity: the stored public key is not the one its private key derives")
	// ErrRoundTripFailed is a key that does not sign and verify as a whole.
	ErrRoundTripFailed = errors.New("identity: the key does not sign and verify")
)

// The tags a key file names a purpose, a profile and a half's algorithm by.
const (
	tagMLDSASeed = 1
	tagRSAPSS    = 2
)

var (
	purposeTags = map[Purpose]byte{PurposeIdentity: 1, PurposeConnect: 2}
	tagPurposes = map[byte]Purpose{1: PurposeIdentity, 2: PurposeConnect}
	profileTags = map[profile.Profile]byte{profile.PQPure: 1, profile.PQHybrid: 2}
	tagProfiles = map[byte]profile.Profile{1: profile.PQPure, 2: profile.PQHybrid}
)

// Save writes k to path in the seed form: the magic, the purpose, profile and
// half count, then each half as its algorithm tag and its public and private
// keys, each length-prefixed in four big-endian bytes. An ML-DSA-87 half keeps
// its 32-byte seed, and an RSA-PSS half its PKCS #1 key. The file is readable
// by its owner only before the key is written into it, and replaces any file
// at path in one rename.
func (k *NodeKey) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("identity: save key: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("identity: save key: %w", err)
	}
	if err := writeRestricted(f, k.fileBytes()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("identity: save key: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("identity: save key: %w", err)
	}
	return nil
}

// writeRestricted makes f readable by its owner only, then writes contents,
// syncs and closes it.
func writeRestricted(f *os.File, contents []byte) error {
	err := f.Chmod(0o600)
	if err == nil {
		_, err = f.Write(contents)
	}
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// fileBytes is k laid out as a key file.
func (k *NodeKey) fileBytes() []byte {
	halves := byte(1)
	if k.rsa != nil {
		halves = 2
	}
	out := append([]byte(keyFileMagic), purposeTags[k.purpose], profileTags[k.profile], halves)
	out = appendHalf(out, tagMLDSASeed, k.mldsa.PublicKey().Bytes(), k.mldsa.Bytes())
	if k.rsa != nil {
		out = appendHalf(out, tagRSAPSS, x509.MarshalPKCS1PublicKey(&k.rsa.PublicKey), x509.MarshalPKCS1PrivateKey(k.rsa))
	}
	return out
}

func appendHalf(out []byte, tag byte, public, private []byte) []byte {
	out = append(out, tag)
	out = binary.BigEndian.AppendUint32(out, uint32(len(public)))
	out = append(out, public...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(private)))
	return append(out, private...)
}

// LoadKey reads the key saved at path for purpose in profile p, and checks it
// before returning it. It refuses a file its group or others can read, a key
// for another purpose or profile, halves that do not fit the profile, a stored
// public key that differs from the one its private key derives, and a key that
// fails a sign-and-verify round trip.
func LoadKey(path string, purpose Purpose, p profile.Profile) (*NodeKey, error) {
	contents, err := readOwnerOnly(path)
	if err != nil {
		return nil, err
	}
	file, err := parseKeyFile(contents)
	if err != nil {
		return nil, err
	}
	key, err := file.checkedKey(purpose, p)
	if err != nil {
		return nil, err
	}
	return key, roundTrip(key)
}

// readOwnerOnly is the contents of the file at path, refused when its group or
// others can read it. The mode is checked on the open file it reads.
func readOwnerOnly(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity: load key: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("identity: load key: %w", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, ErrKeyFilePermissions
	}
	var contents bytes.Buffer
	if _, err := contents.ReadFrom(f); err != nil {
		return nil, fmt.Errorf("identity: load key: %w", err)
	}
	return contents.Bytes(), nil
}

// keyFile is a key file as read, before its halves are checked.
type keyFile struct {
	purpose Purpose
	profile profile.Profile
	halves  []storedHalf
}

// storedHalf is one half of a key as a key file holds it.
type storedHalf struct {
	tag     byte
	public  []byte
	private []byte
}

func parseKeyFile(b []byte) (keyFile, error) {
	rest, ok := bytes.CutPrefix(b, []byte(keyFileMagic))
	if !ok || len(rest) < 3 {
		return keyFile{}, ErrBadKeyFile
	}
	purpose, knownPurpose := tagPurposes[rest[0]]
	p, knownProfile := tagProfiles[rest[1]]
	count := int(rest[2])
	if !knownPurpose || !knownProfile {
		return keyFile{}, ErrBadKeyFile
	}
	halves, err := parseHalves(rest[3:])
	if err != nil || len(halves) != count {
		return keyFile{}, ErrBadKeyFile
	}
	return keyFile{purpose: purpose, profile: p, halves: halves}, nil
}

// parseHalves is every half in b, which must end exactly after the last one.
func parseHalves(b []byte) ([]storedHalf, error) {
	var halves []storedHalf
	for len(b) > 0 {
		half, rest, err := parseHalf(b)
		if err != nil {
			return nil, err
		}
		halves = append(halves, half)
		b = rest
	}
	return halves, nil
}

func parseHalf(b []byte) (storedHalf, []byte, error) {
	if b[0] != tagMLDSASeed && b[0] != tagRSAPSS {
		return storedHalf{}, nil, ErrBadKeyFile
	}
	public, rest, ok := lengthPrefixed(b[1:])
	if !ok {
		return storedHalf{}, nil, ErrBadKeyFile
	}
	private, rest, ok := lengthPrefixed(rest)
	if !ok {
		return storedHalf{}, nil, ErrBadKeyFile
	}
	return storedHalf{tag: b[0], public: public, private: private}, rest, nil
}

// lengthPrefixed is the field b starts with, after its four-byte big-endian
// length, and what follows it.
func lengthPrefixed(b []byte) (field, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// checkedKey is the key a file holds, when it is for purpose in profile p and
// every half derives the public key stored beside it.
func (f keyFile) checkedKey(purpose Purpose, p profile.Profile) (*NodeKey, error) {
	if f.purpose != purpose {
		return nil, fmt.Errorf("%w: %s", ErrWrongPurpose, f.purpose)
	}
	if f.profile != p {
		return nil, fmt.Errorf("%w: %s", ErrWrongProfile, f.profile)
	}
	definition, err := p.Definition()
	if err != nil {
		return nil, err
	}
	if !f.halvesFit(definition.Hybrid) {
		return nil, ErrWrongAlgorithms
	}
	mldsaKey, err := mldsaFromHalf(f.halves[0])
	if err != nil {
		return nil, err
	}
	key := &NodeKey{purpose: purpose, profile: p, mldsa: mldsaKey}
	if definition.Hybrid {
		if key.rsa, err = rsaFromHalf(f.halves[1]); err != nil {
			return nil, err
		}
	}
	return key, nil
}

// halvesFit reports whether the file's halves are the profile's: an ML-DSA-87
// seed, followed in pq_hybrid by an RSA-PSS key.
func (f keyFile) halvesFit(hybrid bool) bool {
	if !hybrid {
		return len(f.halves) == 1 && f.halves[0].tag == tagMLDSASeed
	}
	return len(f.halves) == 2 && f.halves[0].tag == tagMLDSASeed && f.halves[1].tag == tagRSAPSS
}

func mldsaFromHalf(h storedHalf) (*mldsa.PrivateKey, error) {
	if len(h.private) != mldsa.PrivateKeySize {
		return nil, ErrPrivateKeyInvalid
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA87(), h.private)
	if err != nil {
		return nil, ErrPrivateKeyInvalid
	}
	if !bytes.Equal(key.PublicKey().Bytes(), h.public) {
		return nil, ErrPublicKeyMismatch
	}
	return key, nil
}

func rsaFromHalf(h storedHalf) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(h.private)
	if err != nil {
		return nil, ErrPrivateKeyInvalid
	}
	if !bytes.Equal(x509.MarshalPKCS1PublicKey(&key.PublicKey), h.public) {
		return nil, ErrPublicKeyMismatch
	}
	if key.N.BitLen() != rsaModulusBits || key.E != rsaPublicExponent {
		return nil, ErrWrongKeySize
	}
	return key, nil
}

// roundTrip signs a random message with the whole key and verifies it. A
// hybrid key signs its composite, never one half on its own.
func roundTrip(key *NodeKey) error {
	message := make([]byte, 32)
	if _, err := rand.Read(message); err != nil {
		return fmt.Errorf("identity: load key: %w", err)
	}
	signature, err := key.Sign(message)
	if err != nil || !Verify(message, signature, key.PublicKey(), key.profile) {
		return ErrRoundTripFailed
	}
	return nil
}
