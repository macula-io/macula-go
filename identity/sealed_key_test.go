package identity

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// TestLoadSealedKey loads a vector's sealed file and its plaintext through the
// path loader: a sealed file opens under either mode, and a plaintext one opens
// under accept and is refused under sealed_required.
func TestLoadSealedKey(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	kek := hexOf(t, v.KEK)
	sealedPath := writtenKeyFile(t, hexOf(t, v.Sealed))
	plaintextPath := writtenKeyFile(t, hexOf(t, v.Plaintext))

	for _, mode := range []KeyFileMode{ModeAccept, ModeSealedRequired} {
		key, err := LoadSealedKey(sealedPath, kek, mode)
		if err != nil {
			t.Fatalf("LoadSealedKey sealed under %s: %v", mode, err)
		}
		if !key.Sealed {
			t.Errorf("sealed file under %s loaded as plaintext", mode)
		}
		if key.Key.KeyID() != arrayOf(t, v.KeyID) {
			t.Errorf("sealed file under %s: key id %x, want %s", mode, key.Key.KeyID(), v.KeyID)
		}
	}

	plain, err := LoadSealedKey(plaintextPath, kek, ModeAccept)
	if err != nil {
		t.Fatalf("LoadSealedKey plaintext under accept: %v", err)
	}
	if plain.Sealed || plain.Key.KeyID() != arrayOf(t, v.KeyID) {
		t.Errorf("plaintext under accept: sealed %t, key id %x, want false and %s", plain.Sealed, plain.Key.KeyID(), v.KeyID)
	}

	if _, err := LoadSealedKey(plaintextPath, kek, ModeSealedRequired); !errors.Is(err, ErrPlaintextKeyRefused) {
		t.Errorf("plaintext under sealed_required: %v, want %v", err, ErrPlaintextKeyRefused)
	}
}

// TestLoadSealedKeyRefusesAModeItDoesNotKnow holds the mode to macula's rule: a
// mode nobody recognises is refused before the file is read, so neither the
// sealed path nor the plaintext one carries on with no opinion. The path does
// not exist, which is how the test tells "the mode was refused" from "the file
// was read".
func TestLoadSealedKeyRefusesAModeItDoesNotKnow(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "no", "such", "key")
	_, err := LoadSealedKey(missing, make([]byte, kekBytes), "sealing")
	if !errors.Is(err, ErrUnknownKeyFileMode) {
		t.Fatalf("%v, want %v", err, ErrUnknownKeyFileMode)
	}
}

// TestUnsealRefusesAHeaderThatLies is the case only a producer can make: the tag
// covers the header, so a header naming a purpose or a key id its own key does
// not have opens, and is refused on what the key says, not on the tag.
func TestUnsealRefusesAHeaderThatLies(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	plaintext, kek, nonce := hexOf(t, v.Plaintext), hexOf(t, v.KEK), hexOf(t, v.Nonce)
	keyID := arrayOf(t, v.KeyID)

	honest := liedHeader(t, purposeTags[PurposeIdentity], keyID, kek, nonce)
	if _, err := UnsealKeyFile(sealOverHeader(t, honest, plaintext, kek, nonce), kek); err != nil {
		t.Fatalf("a hand-built accurate header is refused: %v", err)
	}

	otherPurpose := liedHeader(t, purposeTags[PurposeConnect], keyID, kek, nonce)
	sealed := sealOverHeader(t, otherPurpose, plaintext, kek, nonce)
	if _, err := UnsealKeyFile(sealed, kek); !errors.Is(err, ErrSealedHeaderMismatch) {
		t.Errorf("a header naming another purpose: %v, want %v", err, ErrSealedHeaderMismatch)
	}

	otherKey := keyID
	otherKey[0] ^= 0xff
	wrongID := liedHeader(t, purposeTags[PurposeIdentity], otherKey, kek, nonce)
	sealed = sealOverHeader(t, wrongID, plaintext, kek, nonce)
	if _, err := UnsealKeyFile(sealed, kek); !errors.Is(err, ErrSealedWrongKeyID) {
		t.Errorf("a header naming another key id: %v, want %v", err, ErrSealedWrongKeyID)
	}
}

// TestSealKeyFileRefuses holds the writer to what it cannot seal: a nonce that
// is not 12 bytes, a KEK that is not 32, and a file that is not a plaintext key
// file at all.
func TestSealKeyFileRefuses(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	plaintext, kek, nonce := hexOf(t, v.Plaintext), hexOf(t, v.KEK), hexOf(t, v.Nonce)

	if _, err := SealKeyFile(plaintext, kek, nonce[:nonceBytes-1]); !errors.Is(err, ErrNonceSize) {
		t.Errorf("a short nonce: %v, want %v", err, ErrNonceSize)
	}
	if _, err := SealKeyFile(plaintext, kek[:kekBytes-1], nonce); !errors.Is(err, ErrKEKSize) {
		t.Errorf("a short KEK: %v, want %v", err, ErrKEKSize)
	}
	if _, err := SealKeyFile([]byte("not a key file"), kek, nonce); !errors.Is(err, ErrBadPlaintextKeyFile) {
		t.Errorf("not a key file: %v, want %v", err, ErrBadPlaintextKeyFile)
	}
	if _, err := UnsealKeyFile(hexOf(t, v.Sealed), kek[:kekBytes-1]); !errors.Is(err, ErrKEKSize) {
		t.Errorf("a short KEK at open: %v, want %v", err, ErrKEKSize)
	}
}

// TestKEKID holds a KEK's id to its derivation, and holds it apart from a key
// id: one label can never be taken for the other.
func TestKEKID(t *testing.T) {
	kek := bytes.Repeat([]byte{7}, kekBytes)
	id, err := KEKID(kek)
	if err != nil {
		t.Fatalf("KEKID: %v", err)
	}
	again, err := KEKID(kek)
	if err != nil || id != again {
		t.Fatalf("KEKID is not the same for one KEK: %v, %v", id, again)
	}
	if id == KeyIDOf(kek, profile.PQPure) {
		t.Error("a KEK's id is the same value as a key id over the same bytes")
	}
	if _, err := KEKID(kek[:kekBytes-1]); !errors.Is(err, ErrKEKSize) {
		t.Errorf("a short KEK: %v, want %v", err, ErrKEKSize)
	}
}

// liedHeader is a sealed file's 100-byte header, written by the caller, over a
// KEK's id and a nonce.
func liedHeader(t *testing.T, purposeTag byte, keyID [32]byte, kek, nonce []byte) []byte {
	t.Helper()
	kekID, err := KEKID(kek)
	if err != nil {
		t.Fatalf("KEKID: %v", err)
	}
	header := append([]byte(sealedKeyMagic), sealedKeyVersion, purposeTag, profileTags[profile.PQPure])
	header = append(header, keyID[:]...)
	header = append(header, kekID[:]...)
	header = append(header, nonce...)
	if len(header) != sealedHeaderBytes {
		t.Fatalf("header is %d bytes, want %d", len(header), sealedHeaderBytes)
	}
	return header
}

// TestSealedKeyPrintsNoKey holds a loaded key to the package's rule: naming it
// shows its purpose, profile, key id and whether it was sealed, and never the
// key file's bytes, whatever the verb and in a log line.
func TestSealedKeyPrintsNoKey(t *testing.T) {
	v := readSealedKeyVectors(t).Vectors[0]
	key, err := UnsealKeyFile(hexOf(t, v.Sealed), hexOf(t, v.KEK))
	if err != nil {
		t.Fatalf("UnsealKeyFile: %v", err)
	}
	named := key.String()
	want := "identity pq_pure key " + v.KeyID + " sealed=true"
	if named != want {
		t.Errorf("String is %q, want %q", named, want)
	}
	for _, verb := range []string{"%v", "%+v", "%s", "%#v"} {
		if printed := sprintf(verb, key); containsBytes(printed, key.KeyFile) {
			t.Errorf("%s prints the key file's bytes", verb)
		}
	}
}

func sprintf(verb string, key SealedKey) string {
	return fmt.Sprintf(verb, key)
}

// containsBytes reports whether printed holds b's bytes as a run of characters,
// which is what a leaked key file would look like in a log line.
func containsBytes(printed string, b []byte) bool {
	return b != nil && strings.Contains(printed, string(b))
}

// TestSealedKeyOfTheSDKsOwnKeyFile is the case that puts this format in this
// SDK's scope: a key this package writes — the seed form NodeKey.Save writes —
// must seal, load back under a mode, and answer a key that signs what the
// original signs. A sealer that only opened macula's file would be a reader of
// another implementation's keys rather than this one's.
func TestSealedKeyOfTheSDKsOwnKeyFile(t *testing.T) {
	original, err := GenerateKey(PurposeIdentity, profile.PQPure)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	plaintext, err := os.ReadFile(savedKeyFile(t, original))
	if err != nil {
		t.Fatalf("read the saved key: %v", err)
	}
	kek := bytes.Repeat([]byte{0x2a}, kekBytes)
	nonce := bytes.Repeat([]byte{0x11}, nonceBytes)

	sealed, err := SealKeyFile(plaintext, kek, nonce)
	if err != nil {
		t.Fatalf("SealKeyFile: %v", err)
	}
	header, err := ParseSealedHeader(sealed)
	if err != nil {
		t.Fatalf("ParseSealedHeader: %v", err)
	}
	if header.KeyID != original.KeyID() {
		t.Errorf("the header names key %x, want %x", header.KeyID, original.KeyID())
	}

	sealedPath := writtenKeyFile(t, sealed)
	loaded, err := LoadSealedKey(sealedPath, kek, ModeSealedRequired)
	if err != nil {
		t.Fatalf("LoadSealedKey: %v", err)
	}
	checkSameKey(t, original, loaded, true)

	plain, err := LoadSealedKey(writtenKeyFile(t, plaintext), kek, ModeAccept)
	if err != nil {
		t.Fatalf("LoadSealedKey plaintext: %v", err)
	}
	checkSameKey(t, original, plain, false)
}

// checkSameKey holds a loaded key to the one it was saved from: the same key id,
// and a signature by either that the other verifies.
func checkSameKey(t *testing.T, original *NodeKey, loaded SealedKey, sealed bool) {
	t.Helper()
	if loaded.Sealed != sealed {
		t.Errorf("sealed %t, want %t", loaded.Sealed, sealed)
	}
	if loaded.Key.KeyID() != original.KeyID() {
		t.Fatalf("key id %x, want %x", loaded.Key.KeyID(), original.KeyID())
	}
	message := []byte("a message the loaded key must sign")
	signature, err := original.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(message, signature, loaded.Key.PublicKey(), profile.PQPure) {
		t.Error("the loaded key does not verify the original's signature")
	}
	signature, err = loaded.Key.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !Verify(message, signature, original.PublicKey(), profile.PQPure) {
		t.Error("the original key does not verify the loaded key's signature")
	}
}

// TestSealKeyFileRefusesAFileWithNoKey holds the reader to a header that names a
// key file holding nothing: a count of no halves is not a key, in either form.
func TestSealKeyFileRefusesAFileWithNoKey(t *testing.T) {
	kek := bytes.Repeat([]byte{0x2a}, kekBytes)
	nonce := bytes.Repeat([]byte{0x11}, nonceBytes)
	for _, magic := range []string{maculaKeyFileMagic, keyFileMagic} {
		empty := append([]byte(magic), purposeTags[PurposeIdentity], profileTags[profile.PQPure], 0)
		if _, err := SealKeyFile(empty, kek, nonce); !errors.Is(err, ErrBadPlaintextKeyFile) {
			t.Errorf("%q with no halves: %v, want %v", magic, err, ErrBadPlaintextKeyFile)
		}
	}
}

// TestSealKeyFileRefusesHalvesThatDoNotFitTheProfile holds the reader to a file
// whose halves are not the ones its profile names: one half under a hybrid
// profile, and two under a pure one, are both refused before anything is sealed.
func TestSealKeyFileRefusesHalvesThatDoNotFitTheProfile(t *testing.T) {
	kek := bytes.Repeat([]byte{0x2a}, kekBytes)
	nonce := bytes.Repeat([]byte{0x11}, nonceBytes)
	one := halfBytes(t, tagMLDSASeed)
	two := one + halfBytes(t, tagRSAPSS)

	for _, tc := range []struct {
		name    string
		profile profile.Profile
		halves  string
		count   byte
	}{
		{"one half under a hybrid profile", profile.PQHybrid, one, 1},
		{"two halves under a pure profile", profile.PQPure, two, 2},
	} {
		file := append([]byte(maculaKeyFileMagic), purposeTags[PurposeIdentity], profileTags[tc.profile], tc.count)
		if _, err := SealKeyFile(append(file, tc.halves...), kek, nonce); !errors.Is(err, ErrBadPlaintextKeyFile) {
			t.Errorf("%s: %v, want %v", tc.name, err, ErrBadPlaintextKeyFile)
		}
	}
}

// halfBytes is one half with the given algorithm tag: a four-byte length and
// its bytes, twice, which is what a key file holds whether or not the bytes are
// a key.
func halfBytes(t *testing.T, tag byte) string {
	t.Helper()
	public, private := []byte("public"), []byte("private")
	out := []byte{tag}
	out = binary.BigEndian.AppendUint32(out, uint32(len(public)))
	out = append(out, public...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(private)))
	return string(append(out, private...))
}
