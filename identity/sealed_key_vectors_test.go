package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// sealedKeyVectors is macula's test/vectors/sealed_key_v1.json (macula
// 3de02259, sha256
// 66bca66a179b6871464ccfd0bc0024e200013d6648d9d50d89750fea19a0696f), copied
// into testdata by scripts/interop/copy_sealed_key_vectors.sh: three sealed key
// files, each with the KEK, nonce and plaintext key file it was made from, and
// the offsets a flipped byte is written at (docs/design/DESIGN_SEALED_KEY_FILE.md,
// "7. Vectors"). Key generation is random, so the committed file is the vector.
type sealedKeyVectors struct {
	Vectors []sealedKeyVector `json:"vectors"`
}

// sealedKeyVector is one sealed file and what made it. Purpose is not a field
// of its own: the header names it, and the name carries it ("identity_", "org_").
type sealedKeyVector struct {
	Name              string `json:"name"`
	Profile           string `json:"profile"`
	Header            string `json:"header"`
	KEKID             string `json:"kek_id"`
	KeyID             string `json:"key_id"`
	FlippedByteOffset int    `json:"flipped_byte_offset"`
	HeaderFlipOffset  int    `json:"header_flip_offset"`
	KEK               string `json:"kek"`
	Nonce             string `json:"nonce"`
	Plaintext         string `json:"plaintext"`
	Sealed            string `json:"sealed"`
}

// TestSealedKeyVectors holds the sealed form to macula's vectors, in both
// directions: a conforming reader unseals a vector's bytes to a key of that
// vector's key id, and a conforming writer seals the vector's plaintext with the
// vector's nonce to exactly those bytes. The header is checked on its own first,
// so a label or an offset mistake shows without a full open.
func TestSealedKeyVectors(t *testing.T) {
	vectors := readSealedKeyVectors(t)
	for _, v := range vectors.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			checkSealedHeader(t, v)
			checkUnsealed(t, v)
			checkSealed(t, v)
		})
	}
	if len(vectors.Vectors) != 3 {
		t.Fatalf("%d vectors, want 3", len(vectors.Vectors))
	}
}

// TestSealedKeyVectorsRefused holds each vector to the refusals every
// implementation runs on it: another KEK, a byte flipped in its ciphertext, a
// byte flipped in its header, and a file shorter than its header.
func TestSealedKeyVectorsRefused(t *testing.T) {
	vectors := readSealedKeyVectors(t)
	for _, v := range vectors.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			checkRefused(t, v)
		})
	}
}

func checkSealedHeader(t *testing.T, v sealedKeyVector) {
	t.Helper()
	sealed := hexOf(t, v.Sealed)
	header, err := ParseSealedHeader(sealed)
	if err != nil {
		t.Fatalf("ParseSealedHeader: %v", err)
	}
	if header.Profile != profile.Profile(v.Profile) {
		t.Errorf("profile %s, want %s", header.Profile, v.Profile)
	}
	if header.KeyID != arrayOf(t, v.KeyID) {
		t.Errorf("key id %x, want %s", header.KeyID, v.KeyID)
	}
	if header.KEKID != arrayOf(t, v.KEKID) {
		t.Errorf("kek id %x, want %s", header.KEKID, v.KEKID)
	}
	if !bytes.Equal(sealed[:sealedHeaderBytes], hexOf(t, v.Header)) {
		t.Errorf("header is not the vector's %s", v.Header)
	}
	if header.Purpose != purposeOf(t, v.Name) {
		t.Errorf("purpose %s, want the one %s names", header.Purpose, v.Name)
	}
}

func checkUnsealed(t *testing.T, v sealedKeyVector) {
	t.Helper()
	key, err := UnsealKeyFile(hexOf(t, v.Sealed), hexOf(t, v.KEK))
	if err != nil {
		t.Fatalf("UnsealKeyFile: %v", err)
	}
	if !key.Sealed {
		t.Error("a sealed file opened as plaintext")
	}
	if key.Key.KeyID() != arrayOf(t, v.KeyID) {
		t.Errorf("key id %x, want %s", key.Key.KeyID(), v.KeyID)
	}
	if !bytes.Equal(key.KeyFile, hexOf(t, v.Plaintext)) {
		t.Error("the plaintext is not the vector's")
	}
}

func checkSealed(t *testing.T, v sealedKeyVector) {
	t.Helper()
	sealed, err := SealKeyFile(hexOf(t, v.Plaintext), hexOf(t, v.KEK), hexOf(t, v.Nonce))
	if err != nil {
		t.Fatalf("SealKeyFile: %v", err)
	}
	if !bytes.Equal(sealed, hexOf(t, v.Sealed)) {
		t.Error("the sealed bytes are not the vector's")
	}
}

func checkRefused(t *testing.T, v sealedKeyVector) {
	t.Helper()
	sealed := hexOf(t, v.Sealed)
	kek := hexOf(t, v.KEK)

	other := append([]byte(nil), kek...)
	other[0] ^= 0xff
	checkSealedRefusal(t, "another KEK", ErrSealedWrongKEK, sealed, other)

	checkSealedRefusal(t, "a flipped ciphertext byte", ErrSealedNotAuthentic, flipAt(t, sealed, v.FlippedByteOffset), kek)
	checkSealedRefusal(t, "a flipped header byte", ErrSealedNotAuthentic, flipAt(t, sealed, v.HeaderFlipOffset), kek)
	checkSealedRefusal(t, "a file shorter than its header", ErrSealedBadFile, sealed[:sealedHeaderBytes-1], kek)
}

func checkSealedRefusal(t *testing.T, what string, want error, sealed, kek []byte) {
	t.Helper()
	_, err := UnsealKeyFile(sealed, kek)
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", what, err, want)
	}
}

// purposeOf is the purpose a vector's name carries: "identity_pq_pure" and
// "identity_pq_hybrid" are identity keys, "org_pq_pure" an org key.
func purposeOf(t *testing.T, name string) Purpose {
	t.Helper()
	switch {
	case bytes.HasPrefix([]byte(name), []byte("identity_")):
		return PurposeIdentity
	case bytes.HasPrefix([]byte(name), []byte("org_")):
		return PurposeOrg
	default:
		t.Fatalf("vector %s names no purpose this test knows", name)
		return ""
	}
}

// flipAt is b with the byte at offset changed, which no sealed file survives.
func flipAt(t *testing.T, b []byte, offset int) []byte {
	t.Helper()
	if offset >= len(b) {
		t.Fatalf("offset %d is past the file's %d bytes", offset, len(b))
	}
	out := append([]byte(nil), b...)
	out[offset] ^= 0xff
	return out
}

func arrayOf(t *testing.T, s string) [32]byte {
	t.Helper()
	var id [32]byte
	copy(id[:], hexOf(t, s))
	return id
}

func hexOf(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func readSealedKeyVectors(t *testing.T) sealedKeyVectors {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata", "sealed_key_v1.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors sealedKeyVectors
	if err := json.Unmarshal(contents, &vectors); err != nil {
		t.Fatalf("decode vectors: %v", err)
	}
	return vectors
}

// sealOverHeader seals plaintext under a header the caller wrote, which is how
// a producer that lies about what it sealed is imitated: the tag covers the
// header, so only a producer can make such a file.
func sealOverHeader(t *testing.T, header, plaintext, kek, nonce []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	return aead.Seal(header, nonce, plaintext, header)
}
