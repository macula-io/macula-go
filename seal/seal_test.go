package seal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/profile"
)

// The sender's side of the key agreement, checked by round trip as the spec
// asks: Go's crypto/mlkem has no seeded encapsulation, so a vector's kem_ct
// cannot be reproduced, only recovered.
func TestSenderSecretRoundTrips(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			key, err := GenerateKey(p)
			if err != nil {
				t.Fatal(err)
			}
			ss, kemCt, err := SenderSecret(key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			want := MLKEMCiphertextSize
			if p == profile.PQHybrid {
				want += P384PointSize
			}
			if len(kemCt) != want {
				t.Fatalf("kem_ct is %d bytes, want %d", len(kemCt), want)
			}
			recovered, err := RecipientSecret(key, kemCt)
			if err != nil {
				t.Fatal(err)
			}
			if recovered != ss {
				t.Fatalf("recipient recovered %x, sender has %x", recovered, ss)
			}
			again, kemCtAgain, err := SenderSecret(key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if again == ss || bytes.Equal(kemCtAgain, kemCt) {
				t.Fatal("two encapsulations to one key gave the same secret or kem_ct")
			}

			// A different recipient key recovers something else: the secret
			// is bound to the key it was sealed to.
			other, err := GenerateKey(p)
			if err != nil {
				t.Fatal(err)
			}
			if otherSs, err := RecipientSecret(other, kemCt); err == nil && otherSs == ss {
				t.Fatal("another recipient key recovered the same secret")
			}
		})
	}
}

func TestRecipientSecretRefuses(t *testing.T) {
	pure, err := GenerateKey(profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	hybrid, err := GenerateKey(profile.PQHybrid)
	if err != nil {
		t.Fatal(err)
	}
	_, pureCt, err := SenderSecret(pure.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	_, hybridCt, err := SenderSecret(hybrid.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	offCurve := bytes.Clone(hybridCt)
	offCurve[len(offCurve)-1] ^= 1
	compressed := bytes.Clone(hybridCt)
	compressed[MLKEMCiphertextSize] = 2

	for name, c := range map[string]struct {
		key   *PrivateKey
		kemCt []byte
	}{
		"a pq_pure kem_ct one byte short":     {pure, pureCt[:len(pureCt)-1]},
		"a pq_hybrid kem_ct to a pure key":    {pure, hybridCt},
		"a pq_pure kem_ct to a hybrid key":    {hybrid, pureCt},
		"a pq_hybrid kem_ct one byte long":    {hybrid, append(bytes.Clone(hybridCt), 0)},
		"an ephemeral point off the curve":    {hybrid, offCurve},
		"an ephemeral point not uncompressed": {hybrid, compressed},
	} {
		if _, err := RecipientSecret(c.key, c.kemCt); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: %v, want ErrRefused", name, err)
		}
	}
}

func TestNewPrivateKeyRefuses(t *testing.T) {
	seed := make([]byte, MLKEMSeedSize)
	scalar, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		profile profile.Profile
		seed    []byte
		p384    []byte
	}{
		"a pq_pure key with a P-384 scalar": {profile.PQPure, seed, scalar.Bytes()},
		"a pq_hybrid key with no P-384":     {profile.PQHybrid, seed, nil},
		"a short ML-KEM seed":               {profile.PQPure, seed[:63], nil},
		"a zero P-384 scalar":               {profile.PQHybrid, seed, make([]byte, 48)},
		"no profile":                        {"", seed, nil},
	} {
		if _, err := NewPrivateKey(c.profile, c.seed, c.p384); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpenRefusesWhatIsNotItsOwn(t *testing.T) {
	var key, otherKey [32]byte
	rand.Read(key[:])
	rand.Read(otherKey[:])
	nonce := RandomNonce()
	sealed := Seal(key, nonce, []byte("aad"), []byte("plain"))
	if len(sealed) != len("plain")+TagSize {
		t.Fatalf("sealed is %d bytes", len(sealed))
	}
	for name, attempt := range map[string]func() ([]byte, error){
		"another key":            func() ([]byte, error) { return Open(otherKey, nonce, []byte("aad"), sealed) },
		"another AAD":            func() ([]byte, error) { return Open(key, nonce, []byte("aae"), sealed) },
		"fewer bytes than a tag": func() ([]byte, error) { return Open(key, nonce, []byte("aad"), sealed[:TagSize-1]) },
		"the tag moved to the front": func() ([]byte, error) {
			return Open(key, nonce, []byte("aad"), append(bytes.Clone(sealed[len(sealed)-TagSize:]), sealed[:len(sealed)-TagSize]...))
		},
	} {
		if _, err := attempt(); !errors.Is(err, ErrRefused) {
			t.Errorf("open with %s: %v, want ErrRefused", name, err)
		}
	}
	if RandomNonce() == nonce {
		t.Fatal("two random nonces are equal")
	}
}

// The caller's stream nonce is its seq as a 96-bit big-endian integer: the
// top four bytes are always zero and the last byte is the low one.
func TestStreamNonceIsBigEndian(t *testing.T) {
	got := StreamNonce(0x0102030405060708)
	want := [12]byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8}
	if got != want {
		t.Fatalf("StreamNonce: %x, want %x", got, want)
	}
}

// The two directions of one stream bind different AAD, so a frame cannot be
// reflected back to its sender.
func TestStreamAADBindsTheDirection(t *testing.T) {
	var requestID [16]byte
	if bytes.Equal(StreamAAD(FrameStreamData, requestID, 0, CallerToProvider), StreamAAD(FrameStreamData, requestID, 0, ProviderToCaller)) {
		t.Fatal("both directions have the same AAD")
	}
}
