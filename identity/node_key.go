package identity

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/macula-io/macula-go/profile"
)

// Purpose is what a node key is for. Each key serves exactly one purpose.
type Purpose string

const (
	// PurposeIdentity is a node's identity key, the key its node_id derives
	// from and that signs its bindings and status statements.
	PurposeIdentity Purpose = "identity"
	// PurposeConnect is a node's CONNECT key, bound to its identity key, which
	// signs the proof of each connection it makes.
	PurposeConnect Purpose = "connect"
)

var (
	// ErrNotAnIdentityKey is a node_id asked of a key that is not an identity
	// key.
	ErrNotAnIdentityKey = errors.New("identity: not an identity key")
	// ErrUnknownPurpose is a purpose other than identity or connect.
	ErrUnknownPurpose = errors.New("identity: not a known key purpose")
	// ErrEmptyNodeKey is a NodeKey that holds no key, such as the zero value.
	ErrEmptyNodeKey = errors.New("identity: the node key holds no key")
)

// PuzzleDifficulty is how many leading zero bits an identity key's node_id
// has: a node generates its identity key for it (GenerateIdentityKey), and
// stations check it.
const PuzzleDifficulty = 8

const (
	mldsaPublicKeySize = 2592
	mldsaSignatureSize = 4627
	rsaModulusBits     = 4096
	rsaPublicExponent  = 65537
	compositePrefix    = "CompositeAlgorithmSignatures2025"
	compositeLabel     = "COMPSIG-MLDSA87-RSA4096-PSS-SHA512"
	nodeIDLabel        = "MACULA-NODE-ID-V1"
	keyIDLabel         = "MACULA-KEY-ID-V1"
)

// pssOptions are the composite's RSA-PSS parameters: SHA-384, MGF1 with
// SHA-384, and a 48-byte salt.
var pssOptions = &rsa.PSSOptions{SaltLength: 48, Hash: crypto.SHA384}

// NodeKey is one of a node's keys in its profile: the ML-DSA-87 half, and in
// pq_hybrid the RSA-PSS-4096 half. It signs as a whole, never with one half on
// its own. Printing or logging it shows its purpose, profile and key id, never
// a private half.
type NodeKey struct {
	purpose Purpose
	profile profile.Profile
	mldsa   *mldsa.PrivateKey
	rsa     *rsa.PrivateKey
}

// GenerateKey is a new key for purpose in profile p. In a binary without ML-DSA
// it returns ErrPostQuantumUnavailable.
func GenerateKey(purpose Purpose, p profile.Profile) (*NodeKey, error) {
	if err := CheckPostQuantum(); err != nil {
		return nil, err
	}
	definition, err := p.Definition()
	if err != nil {
		return nil, err
	}
	if purpose != PurposeIdentity && purpose != PurposeConnect {
		return nil, fmt.Errorf("%w: %q", ErrUnknownPurpose, string(purpose))
	}
	half, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("identity: generate an ML-DSA-87 key: %w", err)
	}
	key := &NodeKey{purpose: purpose, profile: p, mldsa: half}
	if !definition.Hybrid {
		return key, nil
	}
	if key.rsa, err = rsa.GenerateKey(rand.Reader, rsaModulusBits); err != nil {
		return nil, fmt.Errorf("identity: generate an RSA-%d key: %w", rsaModulusBits, err)
	}
	return key, nil
}

// GenerateIdentityKey is a new identity key in profile p whose node_id starts
// with difficulty zero bits, found in about 2^difficulty tries. Each try makes
// a new ML-DSA-87 half; a pq_hybrid key keeps its RSA-PSS half, since the
// node_id covers both.
func GenerateIdentityKey(p profile.Profile, difficulty int) (*NodeKey, error) {
	return GenerateIdentityKeyContext(context.Background(), p, difficulty)
}

// GenerateIdentityKeyContext is GenerateIdentityKey that gives up with the
// context's error once ctx ends, checked between puzzle candidates.
func GenerateIdentityKeyContext(ctx context.Context, p profile.Profile, difficulty int) (*NodeKey, error) {
	if difficulty < 0 || difficulty > 256 {
		return nil, fmt.Errorf("identity: puzzle difficulty %d is outside 0 to 256", difficulty)
	}
	key, err := GenerateKey(PurposeIdentity, p)
	for err == nil && !PuzzleSolved(NodeIDOf(key.PublicKey(), p), difficulty) {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		key, err = key.puzzleCandidate()
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

// puzzleCandidate is k with a new ML-DSA-87 half and its RSA-PSS half kept.
func (k *NodeKey) puzzleCandidate() (*NodeKey, error) {
	half, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		return nil, fmt.Errorf("identity: generate an ML-DSA-87 key: %w", err)
	}
	return &NodeKey{purpose: k.purpose, profile: k.profile, mldsa: half, rsa: k.rsa}, nil
}

// Purpose is what k is for.
func (k *NodeKey) Purpose() Purpose { return k.purpose }

// Profile is the profile k belongs to.
func (k *NodeKey) Profile() profile.Profile { return k.profile }

// PublicKey is k as carried (D13): the 2,592-byte ML-DSA-87 key, followed in
// pq_hybrid by the DER RSAPublicKey. An empty or nil key has none.
func (k *NodeKey) PublicKey() []byte {
	if k == nil || k.mldsa == nil {
		return nil
	}
	carried := bytes.Clone(k.mldsa.PublicKey().Bytes())
	if k.rsa == nil {
		return carried
	}
	return append(carried, x509.MarshalPKCS1PublicKey(&k.rsa.PublicKey)...)
}

// NodeID is the node_id of an identity key (D5), or ErrNotAnIdentityKey.
func (k *NodeKey) NodeID() ([32]byte, error) {
	if k.purpose != PurposeIdentity {
		return [32]byte{}, ErrNotAnIdentityKey
	}
	return NodeIDOf(k.PublicKey(), k.profile), nil
}

// KeyID names k in signed objects: an identity key's node_id, and the key id
// of any other key.
func (k *NodeKey) KeyID() [32]byte {
	if k.purpose == PurposeIdentity {
		return NodeIDOf(k.PublicKey(), k.profile)
	}
	return KeyIDOf(k.PublicKey(), k.profile)
}

// Sign signs message: with ML-DSA-87 alone in pq_pure, and in pq_hybrid with
// the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512 (as macula 12 signs it),
// where both halves sign the message representative, the ML-DSA-87 half with
// the composite label as its context, and the signature is the ML-DSA-87
// signature followed by the RSA-PSS signature. An empty or nil key refuses
// with ErrEmptyNodeKey.
func (k *NodeKey) Sign(message []byte) ([]byte, error) {
	if k == nil || k.mldsa == nil {
		return nil, ErrEmptyNodeKey
	}
	if k.rsa == nil {
		return k.mldsa.Sign(rand.Reader, message, crypto.Hash(0))
	}
	representative := compositeRepresentative(message)
	mldsaSignature, err := k.mldsa.Sign(rand.Reader, representative, compositeMLDSAOptions)
	if err != nil {
		return nil, fmt.Errorf("identity: sign the ML-DSA-87 half: %w", err)
	}
	digest := sha512.Sum384(representative)
	rsaSignature, err := rsa.SignPSS(rand.Reader, k.rsa, crypto.SHA384, digest[:], pssOptions)
	if err != nil {
		return nil, fmt.Errorf("identity: sign the RSA-PSS half: %w", err)
	}
	return append(mldsaSignature, rsaSignature...), nil
}

// Verify reports whether signature is valid over message for a key as carried,
// under profile p: an ML-DSA-87 signature in pq_pure, and in pq_hybrid a
// composite whose two halves both verify, with the key in its one carried form.
// Malformed input is refused, never panicked on. In a binary without ML-DSA
// (see CheckPostQuantum) it returns false for every signature; the verifiers
// that return an error, VerifyTLSBinding, VerifyConnectBinding, VerifyStatus,
// VerifyObject and VerifyHeldObject, return ErrPostQuantumUnavailable there.
func Verify(message, signature, carriedKey []byte, p profile.Profile) bool {
	definition, err := p.Definition()
	if err != nil {
		return false
	}
	if !definition.Hybrid {
		return len(signature) == mldsaSignatureSize && verifyMLDSA(carriedKey, message, signature)
	}
	if len(signature) != SignatureSize(p) || !CarriedKeyWellFormed(carriedKey, p) {
		return false
	}
	rsaPublic, err := x509.ParsePKCS1PublicKey(carriedKey[mldsaPublicKeySize:])
	if err != nil {
		return false
	}
	representative := compositeRepresentative(message)
	digest := sha512.Sum384(representative)
	mldsaValid := verifyMLDSAWith(carriedKey[:mldsaPublicKeySize], representative, signature[:mldsaSignatureSize], compositeMLDSAOptions)
	rsaValid := rsa.VerifyPSS(rsaPublic, crypto.SHA384, digest[:], signature[mldsaSignatureSize:], pssOptions) == nil
	return mldsaValid && rsaValid
}

// compositeMLDSAOptions is the composite's ML-DSA-87 context: the composite
// label itself, as the LAMPS draft and macula 12 sign it.
var compositeMLDSAOptions = &mldsa.Options{Context: compositeLabel}

// verifyMLDSA reports whether signature is an ML-DSA-87 signature over message,
// with an empty context, by the 2,592-byte public key.
func verifyMLDSA(public, message, signature []byte) bool {
	return verifyMLDSAWith(public, message, signature, nil)
}

// verifyMLDSAWith is verifyMLDSA under the given options (nil: empty context).
func verifyMLDSAWith(public, message, signature []byte, opts *mldsa.Options) bool {
	if len(public) != mldsaPublicKeySize {
		return false
	}
	key, err := mldsa.NewPublicKey(mldsa.MLDSA87(), public)
	return err == nil && mldsa.Verify(key, message, signature, opts) == nil
}

// CarriedKeyWellFormed reports whether key is a key in its one carried form for
// profile p (D13): exactly 2,592 bytes in pq_pure, and in pq_hybrid the
// ML-DSA-87 key followed by a DER RSAPublicKey that encodes back to the same
// bytes, with a 4,096-bit modulus and exponent 65537. It says nothing about
// who holds the key.
func CarriedKeyWellFormed(key []byte, p profile.Profile) bool {
	definition, err := p.Definition()
	if err != nil {
		return false
	}
	if !definition.Hybrid {
		return len(key) == mldsaPublicKeySize
	}
	if len(key) <= mldsaPublicKeySize {
		return false
	}
	der := key[mldsaPublicKeySize:]
	public, err := x509.ParsePKCS1PublicKey(der)
	if err != nil {
		return false
	}
	return public.N.BitLen() == rsaModulusBits && public.E == rsaPublicExponent &&
		bytes.Equal(x509.MarshalPKCS1PublicKey(public), der)
}

// SignatureSize is the size of a signature by a node key in profile p: the
// ML-DSA-87 signature, followed in pq_hybrid by an RSA-PSS signature as long as
// the modulus. It is 0 for an unknown profile.
func SignatureSize(p profile.Profile) int {
	definition, err := p.Definition()
	switch {
	case err != nil:
		return 0
	case definition.Hybrid:
		return mldsaSignatureSize + rsaModulusBits/8
	default:
		return mldsaSignatureSize
	}
}

// NodeIDOf is the node_id of an identity key as carried, under profile p (D5).
// A node_id earns no trust on its own: rely on it only after a signature by the
// same carried key has verified.
func NodeIDOf(carriedKey []byte, p profile.Profile) [32]byte {
	return labelledID(nodeIDLabel, carriedKey, p)
}

// KeyIDOf is the key id of a key as carried that is not an identity key, under
// profile p. Like a node_id, it earns no trust on its own.
func KeyIDOf(carriedKey []byte, p profile.Profile) [32]byte {
	return labelledID(keyIDLabel, carriedKey, p)
}

// labelledID is SHA-256 over label, a zero byte, the length and ASCII name of
// profile p, and a key as carried.
func labelledID(label string, carriedKey []byte, p profile.Profile) [32]byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0, byte(len(p))})
	h.Write([]byte(p))
	h.Write(carriedKey)
	var id [32]byte
	copy(id[:], h.Sum(nil))
	return id
}

// PuzzleSolved reports whether nodeID starts with difficulty zero bits. A
// difficulty outside 0 to 256 is never solved.
func PuzzleSolved(nodeID [32]byte, difficulty int) bool {
	if difficulty < 0 || difficulty > 256 {
		return false
	}
	whole, rest := difficulty/8, difficulty%8
	for _, b := range nodeID[:whole] {
		if b != 0 {
			return false
		}
	}
	return rest == 0 || nodeID[whole]>>(8-rest) == 0
}

// compositeRepresentative is the message both halves of a composite sign:
// the prefix, the label, a zero byte for the empty application context, and
// the SHA-512 of the message.
func compositeRepresentative(message []byte) []byte {
	digest := sha512.Sum512(message)
	out := make([]byte, 0, len(compositePrefix)+len(compositeLabel)+1+len(digest))
	out = append(out, compositePrefix...)
	out = append(out, compositeLabel...)
	out = append(out, 0)
	return append(out, digest[:]...)
}

// String names the key by its purpose, profile and key id. It never shows a
// private half.
func (k NodeKey) String() string {
	if k.mldsa == nil {
		return "empty node key"
	}
	id := k.KeyID()
	return fmt.Sprintf("%s %s key %s", k.purpose, k.profile, hex.EncodeToString(id[:]))
}

// Format writes the key as String does, whatever the verb.
func (k NodeKey) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, k.String())
}

// LogValue logs the key as String does.
func (k NodeKey) LogValue() slog.Value {
	return slog.StringValue(k.String())
}
