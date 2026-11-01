package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"github.com/macula-io/macula-go/profile"
)

// A sealed key file (MACULA-SEALED-KEY-V1) is macula's key file encrypted with
// AES-256-GCM under a key-encryption key the deployment supplies from off the
// key's own volume, so a copy of the file is not a working identity. Sealing
// changes no identity: the key id inside, the node_id it derives and every
// signature stay exactly what they were.
//
// This is the Go half of WP-K2 of macula-io/macula-realm#176. The design of
// record is macula's docs/design/DESIGN_SEALED_KEY_FILE.md, and
// testdata/sealed_key_v1.json is the contract the Erlang, Go and Rust
// implementations are held to: a conforming reader unseals a vector's sealed
// bytes to a key of that vector's key id, and a conforming writer seals the
// vector's plaintext with the vector's nonce to exactly those bytes.
//
// The file is a 100-byte header, then the plaintext key file's ciphertext and
// its 16-byte GCM tag. The header is the whole of the additional authenticated
// data, so a byte changed anywhere in it fails the tag as well.
//
//	offset  bytes  field
//	0       21     "MACULA-SEALED-KEY-V1" and a NUL
//	21      1      format version, 1
//	22      1      purpose tag, 1 identity 2 connect 3 tls 4 realm 5 org 6 foundation
//	23      1      profile tag, 1 pq_pure 2 pq_hybrid
//	24      32     the key id of the key inside
//	56      32     the KEK's id
//	88      12     the nonce
//	100     n      the ciphertext of the plaintext key file, then its 16-byte tag
const (
	sealedKeyMagic    = "MACULA-SEALED-KEY-V1\x00"
	sealedKeyVersion  = 1
	sealedHeaderBytes = 100
	kekBytes          = 32
	nonceBytes        = 12
	gcmTagBytes       = 16
	kekIDLabel        = "MACULA-KEK-ID-V1"
	// maculaKeyFileMagic opens the plaintext key file a sealed file holds.
	// It is macula's own key file (the expanded key), not this package's seed
	// form, so sealing is written over the format a deployment already has.
	maculaKeyFileMagic = "macula-node-key-v1\x00"
)

// The refusals of the sealed form. Each names the step that failed, so an
// operator can act on it: a wrong KEK is a KEK to find, an unauthentic file is
// a file to replace.
var (
	// ErrSealedBadFile is a file that does not open with the sealed magic, or
	// is shorter than the header.
	ErrSealedBadFile = errors.New("identity: not a sealed key file")
	// ErrSealedWrongKEK is a file sealed to a KEK other than the one supplied.
	// The header names the KEK, so this is decided before the tag is checked.
	ErrSealedWrongKEK = errors.New("identity: the sealed key file was sealed to another KEK")
	// ErrSealedNotAuthentic is a file altered since it was sealed, anywhere in
	// its header or its ciphertext.
	ErrSealedNotAuthentic = errors.New("identity: the sealed key file has been altered since it was sealed")
	// ErrSealedHeaderMismatch is a file whose header names a purpose or profile
	// its own key disagrees with.
	ErrSealedHeaderMismatch = errors.New("identity: the sealed key file's header and key disagree")
	// ErrSealedWrongKeyID is a file whose header names a key id its own key does
	// not derive.
	ErrSealedWrongKeyID = errors.New("identity: the sealed key file's key id is not the one inside it")
	// ErrBadPlaintextKeyFile is a file that is not macula's plaintext key file.
	ErrBadPlaintextKeyFile = errors.New("identity: not a plaintext key file")
	// ErrKEKSize is a KEK that is not 32 bytes.
	ErrKEKSize = errors.New("identity: the KEK is not 32 bytes")
	// ErrNonceSize is a nonce that is not 12 bytes.
	ErrNonceSize = errors.New("identity: the nonce is not 12 bytes")
	// ErrPlaintextKeyRefused is a plaintext key file loaded in sealed_required.
	ErrPlaintextKeyRefused = errors.New("identity: the key file is plaintext and the mode is sealed_required")
	// ErrUnknownKeyFileMode is a mode other than accept or sealed_required.
	ErrUnknownKeyFileMode = errors.New("identity: not a known key file mode")
)

// SealedHeader is what a sealed file says about itself, which an operator can
// read without a KEK: which purpose and profile the key is for, which key it
// holds, and which KEK it was sealed to. It is the file's first 100 bytes, and
// the whole of the AEAD's additional authenticated data.
type SealedHeader struct {
	Purpose Purpose
	Profile profile.Profile
	KeyID   [32]byte
	KEKID   [32]byte
	Nonce   [12]byte
}

// SealedKey is a key file as loaded: what it holds, and whether it was sealed.
// Plaintext is the plaintext key file's bytes, which for a live key are its
// private halves; it is returned so a caller can hand them to the loader that
// owns the key's format.
type SealedKey struct {
	Purpose   Purpose
	Profile   profile.Profile
	KeyID     [32]byte
	Sealed    bool
	Plaintext []byte
}

// KEKID is a KEK's id: SHA-256 over the label MACULA-KEK-ID-V1, a zero byte
// and the KEK, labelled the way a key id is so one can never be taken for the
// other. It names which KEK a sealed file was sealed to.
func KEKID(kek []byte) ([32]byte, error) {
	if len(kek) != kekBytes {
		return [32]byte{}, ErrKEKSize
	}
	h := sha256.New()
	h.Write([]byte(kekIDLabel))
	h.Write([]byte{0})
	h.Write(kek)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id, nil
}

// SealKeyFile seals plaintext, macula's plaintext key file, under kek and
// nonce, and answers the sealed file. The nonce is the caller's so that a
// vector can be reproduced byte for byte; a deployment seals with a fresh
// random one.
//
// A nonce is never reused under one KEK: two files sealed with the same KEK and
// nonce give away the XOR of their plaintexts.
func SealKeyFile(plaintext, kek, nonce []byte) ([]byte, error) {
	key, err := parseMaculaKeyFile(plaintext)
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceBytes {
		return nil, ErrNonceSize
	}
	header, err := sealHeader(key, kek, nonce)
	if err != nil {
		return nil, err
	}
	aead, err := sealedAEAD(kek)
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, nonce, plaintext, header), nil
}

// UnsealKeyFile opens a sealed file with kek and answers the plaintext key file,
// once the header's KEK id, purpose, profile and key id have each been held to
// what the file itself says.
func UnsealKeyFile(sealed, kek []byte) (SealedKey, error) {
	header, ciphertext, err := splitSealed(sealed)
	if err != nil {
		return SealedKey{}, err
	}
	want, err := KEKID(kek)
	if err != nil {
		return SealedKey{}, err
	}
	if header.KEKID != want {
		return SealedKey{}, ErrSealedWrongKEK
	}
	plaintext, err := openSealed(sealed[:sealedHeaderBytes], ciphertext, header.Nonce, kek)
	if err != nil {
		return SealedKey{}, err
	}
	key, err := parseMaculaKeyFile(plaintext)
	if err != nil {
		return SealedKey{}, err
	}
	if key.Purpose != header.Purpose || key.Profile != header.Profile {
		return SealedKey{}, ErrSealedHeaderMismatch
	}
	keyID := key.keyID()
	if keyID != header.KeyID {
		return SealedKey{}, ErrSealedWrongKeyID
	}
	return SealedKey{Purpose: key.Purpose, Profile: key.Profile, KeyID: keyID, Sealed: true, Plaintext: plaintext}, nil
}

// ParseSealedHeader is what a sealed file says about itself, from its first
// bytes and without a KEK. It reads the header only: it does not open the file,
// so a header that names the right shapes over bytes that are not the key they
// claim is answered here and refused by UnsealKeyFile.
func ParseSealedHeader(sealed []byte) (SealedHeader, error) {
	header, _, err := splitSealed(sealed)
	return header, err
}

// sealHeader builds the header SealKeyFile puts over key, sealed with kek under
// nonce.
func sealHeader(key maculaKeyFile, kek, nonce []byte) ([]byte, error) {
	kekID, err := KEKID(kek)
	if err != nil {
		return nil, err
	}
	keyID := key.keyID()
	out := make([]byte, 0, sealedHeaderBytes)
	out = append(out, sealedKeyMagic...)
	out = append(out, sealedKeyVersion, purposeTags[key.Purpose], profileTags[key.Profile])
	out = append(out, keyID[:]...)
	out = append(out, kekID[:]...)
	return append(out, nonce...), nil
}

// splitSealed is the header of a sealed file and the ciphertext that follows it.
func splitSealed(sealed []byte) (SealedHeader, []byte, error) {
	rest, ok := bytes.CutPrefix(sealed, []byte(sealedKeyMagic))
	if !ok {
		return SealedHeader{}, nil, ErrSealedBadFile
	}
	return sealedHeader(rest)
}

// sealedHeader reads the 100-byte header from the bytes after the magic.
func sealedHeader(rest []byte) (SealedHeader, []byte, error) {
	if len(rest) < sealedHeaderBytes-len(sealedKeyMagic) {
		return SealedHeader{}, nil, ErrSealedBadFile
	}
	version, purposeTag, profileTag := rest[0], rest[1], rest[2]
	purpose, knownPurpose := tagPurposes[purposeTag]
	p, knownProfile := tagProfiles[profileTag]
	if version != sealedKeyVersion || !knownPurpose || !knownProfile {
		return SealedHeader{}, nil, ErrSealedBadFile
	}
	header := SealedHeader{Purpose: purpose, Profile: p}
	copy(header.KeyID[:], rest[3:3+32])
	copy(header.KEKID[:], rest[3+32:3+64])
	copy(header.Nonce[:], rest[3+64:3+76])
	return header, rest[3+76:], nil
}

// openSealed is the plaintext under a sealed file's header and ciphertext.
func openSealed(headered, ciphertext []byte, nonce [12]byte, kek []byte) ([]byte, error) {
	aead, err := sealedAEAD(kek)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce[:], ciphertext, headered)
	if err != nil {
		return nil, ErrSealedNotAuthentic
	}
	return plaintext, nil
}

// sealedAEAD is AES-256-GCM under kek.
func sealedAEAD(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrKEKSize
	}
	return cipher.NewGCM(block)
}

// maculaKeyFile is a plaintext key file as macula writes it: the magic, the
// purpose, the profile and the components, each a tagged public half and its
// private half. Only what the sealed form needs is modelled — the purposes,
// the profile and the halves' public bytes, which are what a key id derives
// from.
type maculaKeyFile struct {
	Purpose Purpose
	Profile profile.Profile
	Halves  []storedHalf
}

// parseMaculaKeyFile is b as macula's plaintext key file, refused unless its
// magic, tags, component count and halves all fit.
func parseMaculaKeyFile(b []byte) (maculaKeyFile, error) {
	rest, ok := bytes.CutPrefix(b, []byte(maculaKeyFileMagic))
	if !ok || len(rest) < 3 {
		return maculaKeyFile{}, ErrBadPlaintextKeyFile
	}
	purpose, knownPurpose := tagPurposes[rest[0]]
	p, knownProfile := tagProfiles[rest[1]]
	if !knownPurpose || !knownProfile {
		return maculaKeyFile{}, ErrBadPlaintextKeyFile
	}
	halves, err := parseHalves(rest[3:])
	if err != nil || len(halves) != int(rest[2]) {
		return maculaKeyFile{}, ErrBadPlaintextKeyFile
	}
	return maculaKeyFile{Purpose: purpose, Profile: p, Halves: halves}, nil
}

// carriedKey is the key as carried: the public half of each component, in
// order, which is what a node_id and a key id derive from.
func (f maculaKeyFile) carriedKey() []byte {
	out := make([]byte, 0, carriedKeyBytes(f.Halves))
	for _, half := range f.Halves {
		out = append(out, half.public...)
	}
	return out
}

func carriedKeyBytes(halves []storedHalf) int {
	total := 0
	for _, half := range halves {
		total += len(half.public)
	}
	return total
}

// keyID is the file's key id: the node_id of an identity key, and any other
// purpose's key id, which is macula's rule for every key it writes.
func (f maculaKeyFile) keyID() [32]byte {
	if f.Purpose == PurposeIdentity {
		return NodeIDOf(f.carriedKey(), f.Profile)
	}
	return KeyIDOf(f.carriedKey(), f.Profile)
}
