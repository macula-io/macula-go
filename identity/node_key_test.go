package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/profile"
	"time"
)

// referenceKeyBytes is length bytes where byte i is i mod 256, the key of
// macula's node_id and key_id reference vectors.
func referenceKeyBytes(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = byte(i % 256)
	}
	return b
}

// flippedAt is b with the byte at offset changed.
func flippedAt(b []byte, offset int) []byte {
	c := bytes.Clone(b)
	c[offset] ^= 1
	return c
}

func fixtureBytes(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "lamps_mldsa87_rsa4096_pss_sha512", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

// One key per profile, shared by the tests that only read it: an RSA-4096 key
// takes seconds to generate.
var (
	pureIdentityKey   = sync.OnceValues(func() (*NodeKey, error) { return GenerateKey(PurposeIdentity, profile.PQPure) })
	hybridIdentityKey = sync.OnceValues(func() (*NodeKey, error) { return GenerateKey(PurposeIdentity, profile.PQHybrid) })
)

func sharedKey(t *testing.T, get func() (*NodeKey, error)) *NodeKey {
	t.Helper()
	key, err := get()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	return key
}

func TestNodeIDMatchesMaculasReferenceVectors(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		p    profile.Profile
		want string
	}{
		{"pq_pure", referenceKeyBytes(2592), profile.PQPure, "8c6a28c62bda0112065bccb0d8b02b18f46fef03d16e8b7ae91086025dd209ff"},
		{"pq_hybrid", referenceKeyBytes(3118), profile.PQHybrid, "e9df1133a8238239c58fc7f886d9667e961449ee272c30e968a0eecbb6b0131c"},
		{"the profile separates node_ids over the same key bytes", referenceKeyBytes(2592), profile.PQHybrid, "4e79818f04bffbd7f2df71b82e3e543458d9f74cda64f88a80b352ed8e9af10b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NodeIDOf(c.key, c.p); hex.EncodeToString(got[:]) != c.want {
				t.Errorf("NodeIDOf = %x, want %s", got, c.want)
			}
		})
	}
}

func TestKeyIDMatchesMaculasReferenceVectors(t *testing.T) {
	cases := []struct {
		name string
		key  []byte
		p    profile.Profile
		want string
	}{
		{"pq_pure", referenceKeyBytes(2592), profile.PQPure, "8bb084a6409125fdd96c2da8c9a2d7accb4507d05f81e4c34424f35aa26c3290"},
		{"pq_hybrid", referenceKeyBytes(3118), profile.PQHybrid, "0f53c958ae40d81c719ec3d90475d12c254fc7bfdecb59cd7a273ed1fdfa0f81"},
		{"the profile separates key ids over the same key bytes", referenceKeyBytes(2592), profile.PQHybrid, "90792cb738943aed2706f7577b0e9d5e96c023dec6ebf6dca90b2221beee606b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := KeyIDOf(c.key, c.p); hex.EncodeToString(got[:]) != c.want {
				t.Errorf("KeyIDOf = %x, want %s", got, c.want)
			}
		})
	}
	if NodeIDOf(referenceKeyBytes(2592), profile.PQPure) == KeyIDOf(referenceKeyBytes(2592), profile.PQPure) {
		t.Error("a node_id and a key id over the same key are equal, want their labels to separate them")
	}
}

// The composite's message representative, byte for byte as macula 12's
// composite_representative/1 builds it: the prefix, the LAMPS label
// COMPSIG-MLDSA87-RSA4096-PSS-SHA512, a zero byte for the empty context, and
// the SHA-512 of the message. The expected bytes were computed on OTP 28.4.3
// from that function's definition.
func TestCompositeRepresentativeMatchesTheSharedVector(t *testing.T) {
	const want = "436f6d706f73697465416c676f726974686d5369676e61747572657332303235" +
		"434f4d505349472d4d4c44534138372d525341343039362d5053532d534841353132" +
		"00" +
		"e4f23edffade3a0a47087a2f675e84d4ed9c126f824e93c09ae81c09033b82d3" +
		"ef4b9c62d5bbc6238b99df1bec305ed30456cd776dca2e8182ecc35e4c72b7f7"
	if got := hex.EncodeToString(compositeRepresentative([]byte("macula-composite-vector"))); got != want {
		t.Fatalf("representative = %s, want %s", got, want)
	}
}

// Composites signed elsewhere verify here, and each alteration is refused: the
// LAMPS draft's own vector, and one macula 12 signed (written by
// scripts/interop/emit_erlang_composite.escript).
func TestCompositeSignaturesMadeElsewhereVerify(t *testing.T) {
	for signer, files := range map[string][3]string{
		"lamps": {"m.bin", "pk.bin", "s.bin"},
		"otp":   {"otp_message.bin", "otp_pk.bin", "otp_sig.bin"},
	} {
		t.Run(signer, func(t *testing.T) {
			message := fixtureBytes(t, files[0])
			public := fixtureBytes(t, files[1])
			signature := fixtureBytes(t, files[2])
			if !Verify(message, signature, public, profile.PQHybrid) {
				t.Fatal("the composite does not verify")
			}
			if Verify(append(bytes.Clone(message), 0), signature, public, profile.PQHybrid) {
				t.Error("another message verifies")
			}
			if Verify(message, flippedAt(signature, 10), public, profile.PQHybrid) {
				t.Error("an altered ML-DSA-87 half verifies")
			}
			if Verify(message, flippedAt(signature, 4627+10), public, profile.PQHybrid) {
				t.Error("an altered RSA-PSS half verifies")
			}
			if Verify(message, signature, public, profile.PQPure) {
				t.Error("the composite verifies under pq_pure")
			}
		})
	}
}

func TestAPQPureKeySignsWithMLDSA87Alone(t *testing.T) {
	key := sharedKey(t, pureIdentityKey)
	message := []byte("a record to sign")
	signature, err := key.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	public := key.PublicKey()
	if len(signature) != 4627 || len(public) != 2592 {
		t.Fatalf("signature %d bytes and key %d bytes, want 4627 and 2592", len(signature), len(public))
	}
	mldsaPublic, err := mldsa.NewPublicKey(mldsa.MLDSA87(), public)
	if err != nil || mldsa.Verify(mldsaPublic, message, signature, nil) != nil {
		t.Errorf("the signature is not plain ML-DSA-87 over the message: %v", err)
	}
	if !Verify(message, signature, public, profile.PQPure) {
		t.Error("the signature does not verify")
	}
	if Verify([]byte("another record"), signature, public, profile.PQPure) {
		t.Error("another message verifies")
	}
	if Verify(message, signature, public, profile.PQHybrid) {
		t.Error("an ML-DSA-87 signature verifies under pq_hybrid")
	}
}

func TestAPQHybridKeySignsWithTheCompositeValidOnlyIfBothHalvesVerify(t *testing.T) {
	key := sharedKey(t, hybridIdentityKey)
	message := []byte("a record to sign")
	signature, err := key.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	public := key.PublicKey()
	if len(signature) != 5139 || len(public) != 3118 {
		t.Fatalf("signature %d bytes and key %d bytes, want 5139 and 3118", len(signature), len(public))
	}
	representative := compositeRepresentative(message)
	mldsaPublic, err := mldsa.NewPublicKey(mldsa.MLDSA87(), public[:2592])
	if err != nil || mldsa.Verify(mldsaPublic, representative, signature[:4627], &mldsa.Options{Context: compositeLabel}) != nil {
		t.Errorf("the ML-DSA-87 half does not sign the representative under the composite label: %v", err)
	}
	if mldsa.Verify(mldsaPublic, representative, signature[:4627], nil) == nil {
		t.Error("the ML-DSA-87 half verifies with an empty context, as the pre-12 composite signed it")
	}
	rsaPublic, err := x509.ParsePKCS1PublicKey(public[2592:])
	if err != nil {
		t.Fatalf("the RSA half of the key: %v", err)
	}
	if rsaPublic.E != 65537 || rsaPublic.N.BitLen() != 4096 {
		t.Errorf("RSA key of %d bits with exponent %d, want 4096 and 65537", rsaPublic.N.BitLen(), rsaPublic.E)
	}
	digest := sha512.Sum384(representative)
	pss := &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}
	if err := rsa.VerifyPSS(rsaPublic, crypto.SHA384, digest[:], signature[4627:], pss); err != nil {
		t.Errorf("the RSA half is not PSS with SHA-384 and a 48-byte salt over the representative: %v", err)
	}
	checks := []struct {
		name      string
		message   []byte
		signature []byte
		public    []byte
		p         profile.Profile
		want      bool
	}{
		{"the composite", message, signature, public, profile.PQHybrid, true},
		{"another message", []byte("another record"), signature, public, profile.PQHybrid, false},
		{"an altered ML-DSA-87 half", message, flippedAt(signature, 10), public, profile.PQHybrid, false},
		{"an altered RSA-PSS half", message, flippedAt(signature, 4627+10), public, profile.PQHybrid, false},
		{"the ML-DSA-87 half on its own", message, signature[:4627], public, profile.PQHybrid, false},
		{"the ML-DSA-87 half as pq_pure", message, signature[:4627], public[:2592], profile.PQPure, false},
		{"the composite under pq_pure", message, signature, public, profile.PQPure, false},
		{"a key with a trailing byte", message, signature, append(bytes.Clone(public), 0), profile.PQHybrid, false},
	}
	for _, c := range checks {
		if got := Verify(c.message, c.signature, c.public, c.p); got != c.want {
			t.Errorf("%s: Verify = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestVerifyRefusesMalformedInputWithoutPanicking(t *testing.T) {
	cases := []struct {
		name      string
		signature []byte
		public    []byte
		p         profile.Profile
	}{
		{"empty", nil, nil, profile.PQPure},
		{"zeros in pq_pure", make([]byte, 4627), make([]byte, 2592), profile.PQPure},
		{"zeros in pq_hybrid", make([]byte, 5139), make([]byte, 3118), profile.PQHybrid},
		{"an unknown profile", []byte("sig"), []byte("key"), profile.Profile("rsa_only")},
	}
	for _, c := range cases {
		if Verify([]byte("m"), c.signature, c.public, c.p) {
			t.Errorf("%s: Verify = true", c.name)
		}
	}
}

func TestSignatureSizeMatchesRealSignatures(t *testing.T) {
	for _, get := range []func() (*NodeKey, error){pureIdentityKey, hybridIdentityKey} {
		key := sharedKey(t, get)
		signature, err := key.Sign([]byte("message"))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if want := SignatureSize(key.Profile()); len(signature) != want {
			t.Errorf("%s: signature of %d bytes, SignatureSize says %d", key.Profile(), len(signature), want)
		}
	}
	if SignatureSize(profile.PQPure) != 4627 || SignatureSize(profile.PQHybrid) != 5139 {
		t.Errorf("SignatureSize = %d and %d, want 4627 and 5139", SignatureSize(profile.PQPure), SignatureSize(profile.PQHybrid))
	}
}

// rsaPublicDER is the DER RSAPublicKey of a modulus and an exponent.
func rsaPublicDER(n *big.Int, e int) []byte {
	return x509.MarshalPKCS1PublicKey(&rsa.PublicKey{N: n, E: e})
}

// longFormLength is a DER SEQUENCE with its two-byte length rewritten in a
// longer form than DER allows.
func longFormLength(der []byte) []byte {
	out := []byte{0x30, 0x83, 0x00, der[2], der[3]}
	return append(out, der[4:]...)
}

func TestACarriedKeyHasExactlyOneFormPerProfile(t *testing.T) {
	pure := sharedKey(t, pureIdentityKey).PublicKey()
	hybrid := sharedKey(t, hybridIdentityKey).PublicKey()
	mldsaHalf, rsaHalf := hybrid[:2592], hybrid[2592:]
	rsaKey, err := x509.ParsePKCS1PublicKey(rsaHalf)
	if err != nil {
		t.Fatalf("RSA half: %v", err)
	}
	smaller, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate RSA-3072: %v", err)
	}
	cases := []struct {
		name string
		key  []byte
		p    profile.Profile
		want bool
	}{
		{"a pq_pure key", pure, profile.PQPure, true},
		{"a pq_pure key one byte short", pure[:2591], profile.PQPure, false},
		{"a pq_pure key with a trailing byte", append(bytes.Clone(pure), 0), profile.PQPure, false},
		{"a pq_hybrid key", hybrid, profile.PQHybrid, true},
		{"a pq_hybrid key under pq_pure", hybrid, profile.PQPure, false},
		{"the ML-DSA-87 half alone under pq_hybrid", mldsaHalf, profile.PQHybrid, false},
		{"an RSA half with a long-form DER length", append(bytes.Clone(mldsaHalf), longFormLength(rsaHalf)...), profile.PQHybrid, false},
		{"an RSA-3072 half", append(bytes.Clone(mldsaHalf), rsaPublicDER(smaller.N, smaller.E)...), profile.PQHybrid, false},
		{"an RSA half with exponent 3", append(bytes.Clone(mldsaHalf), rsaPublicDER(rsaKey.N, 3)...), profile.PQHybrid, false},
	}
	for _, c := range cases {
		if got := CarriedKeyWellFormed(c.key, c.p); got != c.want {
			t.Errorf("%s: CarriedKeyWellFormed = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAnIdentityKeysNodeIDIsItsKeyIDAndDerivesFromItsCarriedKey(t *testing.T) {
	for _, get := range []func() (*NodeKey, error){pureIdentityKey, hybridIdentityKey} {
		key := sharedKey(t, get)
		nodeID, err := key.NodeID()
		if err != nil {
			t.Fatalf("%s: NodeID: %v", key.Profile(), err)
		}
		if nodeID != NodeIDOf(key.PublicKey(), key.Profile()) || key.KeyID() != nodeID {
			t.Errorf("%s: node_id %x, key id %x, want both the node_id of the carried key", key.Profile(), nodeID, key.KeyID())
		}
	}
}

func TestAPQHybridNodeIDCoversBothHalves(t *testing.T) {
	key := sharedKey(t, hybridIdentityKey)
	nodeID, _ := key.NodeID()
	public := key.PublicKey()
	if NodeIDOf(flippedAt(public, len(public)-1), profile.PQHybrid) == nodeID {
		t.Error("changing the RSA half keeps the node_id")
	}
	if NodeIDOf(public[:2592], profile.PQHybrid) == nodeID {
		t.Error("the ML-DSA-87 half alone has the node_id")
	}
}

func TestAConnectKeyHasNoNodeIDAndIsNamedByItsKeyID(t *testing.T) {
	key, err := GenerateKey(PurposeConnect, profile.PQPure)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := key.NodeID(); !errors.Is(err, ErrNotAnIdentityKey) {
		t.Errorf("NodeID of a CONNECT key: %v, want ErrNotAnIdentityKey", err)
	}
	if key.KeyID() != KeyIDOf(key.PublicKey(), profile.PQPure) {
		t.Error("a CONNECT key's key id is not the key id of its carried key")
	}
}

func TestGenerateKeyRefusesAnUnknownProfileOrPurpose(t *testing.T) {
	if _, err := GenerateKey(PurposeIdentity, profile.Profile("rsa_only")); !errors.Is(err, profile.ErrUnknown) {
		t.Errorf("an unknown profile: %v, want profile.ErrUnknown", err)
	}
	if _, err := GenerateKey(Purpose("signing"), profile.PQPure); !errors.Is(err, ErrUnknownPurpose) {
		t.Errorf("an unknown purpose: %v, want ErrUnknownPurpose", err)
	}
}

func TestPuzzleSolvedCountsLeadingZeroBits(t *testing.T) {
	var ones [32]byte
	ones[0] = 0xFF
	elevenZeros := [32]byte{0x00, 0x10, 0xFF}
	var zeros [32]byte
	cases := []struct {
		name       string
		nodeID     [32]byte
		difficulty int
		want       bool
	}{
		{"difficulty 0 is always solved", ones, 0, true},
		{"11 leading zero bits meet 11", elevenZeros, 11, true},
		{"11 leading zero bits miss 12", elevenZeros, 12, false},
		{"an all-zero node_id meets 256", zeros, 256, true},
		{"a difficulty past the node_id is never solved", zeros, 257, false},
		{"a negative difficulty is never solved", zeros, -1, false},
	}
	for _, c := range cases {
		if got := PuzzleSolved(c.nodeID, c.difficulty); got != c.want {
			t.Errorf("%s: PuzzleSolved = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAPuzzleKeyMeetsItsDifficultyAndSignsAsAWhole(t *testing.T) {
	for _, c := range []struct {
		p          profile.Profile
		difficulty int
	}{{profile.PQPure, 8}, {profile.PQHybrid, 6}} {
		key, err := GenerateIdentityKey(c.p, c.difficulty)
		if err != nil {
			t.Fatalf("%s: GenerateIdentityKey: %v", c.p, err)
		}
		nodeID, _ := key.NodeID()
		if !PuzzleSolved(nodeID, c.difficulty) {
			t.Errorf("%s: node_id %x misses difficulty %d", c.p, nodeID, c.difficulty)
		}
		message := []byte("signed by the whole puzzle key")
		signature, err := key.Sign(message)
		if err != nil || !Verify(message, signature, key.PublicKey(), c.p) {
			t.Errorf("%s: the puzzle key does not sign and verify as a whole: %v", c.p, err)
		}
	}
}

// Each puzzle try makes a new ML-DSA-87 half and keeps the RSA-PSS half.
func TestEachPuzzleTryChangesTheMLDSAHalfAndKeepsTheRSAHalf(t *testing.T) {
	key := sharedKey(t, hybridIdentityKey)
	next, err := key.puzzleCandidate()
	if err != nil {
		t.Fatalf("puzzleCandidate: %v", err)
	}
	if !bytes.Equal(key.PublicKey()[2592:], next.PublicKey()[2592:]) {
		t.Error("a try changed the RSA-PSS half")
	}
	if bytes.Equal(key.PublicKey()[:2592], next.PublicKey()[:2592]) {
		t.Error("a try kept the ML-DSA-87 half")
	}
	if a, _ := key.NodeID(); func() bool { b, _ := next.NodeID(); return a == b }() {
		t.Error("a try kept the node_id")
	}
}

// Printing or logging a node key never shows a private half.
func TestANodeKeyNeverShowsItsPrivateHalves(t *testing.T) {
	key := sharedKey(t, hybridIdentityKey)
	secrets := []string{
		hex.EncodeToString(key.mldsa.Bytes()),
		key.rsa.D.String(),
		key.rsa.D.Text(16),
		key.rsa.Primes[0].String(),
	}
	var logged strings.Builder
	slog.New(slog.NewTextHandler(&logged, nil)).Info("key", "key", key, "value", *key)
	shown := []string{
		fmt.Sprintf("%v %+v %#v %s %x", key, key, key, key, key),
		fmt.Sprintf("%v %+v %#v %s %x", *key, *key, *key, *key, *key),
		logged.String(),
	}
	for _, out := range shown {
		for _, secret := range secrets {
			if strings.Contains(out, secret) {
				t.Fatalf("a private half shows in %q", out)
			}
		}
	}
	if !strings.Contains(shown[0], hex.EncodeToString(func() []byte { id := key.KeyID(); return id[:] }())) {
		t.Errorf("the key shows as %q, want it named by its key id", shown[0])
	}
}

// GenerateIdentityKeyContext gives up between puzzle candidates once its
// context ends: at difficulty 256 no candidate solves, so only the context
// ends the search.
func TestGenerateIdentityKeyContextEndsWithItsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	key, err := GenerateIdentityKeyContext(ctx, profile.PQPure, 256)
	if !errors.Is(err, context.DeadlineExceeded) || key != nil {
		t.Fatalf("got %v, %v; want context.DeadlineExceeded", key, err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("it took %v to notice its context ended", elapsed)
	}
}
