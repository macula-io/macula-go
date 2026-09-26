// Package seal is end-to-end payload sealing, scheme 1: what a node needs to
// seal a payload so that the stations relaying it cannot read it, the Go
// counterpart of macula's macula_seal. The byte-exact construction is
// macula's test/vectors/E2E_SEAL_V1.md (copied into testdata), and this
// package reproduces that file's vectors.
//
// The key agreement is ML-KEM-1024 in pq_pure, and ML-KEM-1024 with an
// ephemeral P-384 ECDH in pq_hybrid, combined with HKDF-SHA-384 over both
// secrets, both ciphertexts and the recipient's key. Payloads are sealed with
// AES-256-GCM. Everything here is a pure function over crypto/mlkem,
// crypto/ecdh, crypto/hkdf and crypto/aes; the frames that carry a sealed
// payload are built elsewhere.
package seal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// Scheme is the sealed map's scheme number this package implements.
const Scheme = 1

const (
	// MLKEMSeedSize is an ML-KEM-1024 private key as a seed, d || z.
	MLKEMSeedSize = mlkem.SeedSize
	// MLKEMCiphertextSize is an ML-KEM-1024 ciphertext.
	MLKEMCiphertextSize = mlkem.CiphertextSize1024
	// P384PointSize is an uncompressed P-384 point.
	P384PointSize = 97
	// KeyHashSize is the SHA-384 of a recipient's key as carried.
	KeyHashSize = sha512.Size384
	// KeyIDSize is the prefix of the key hash a sealed payload names its
	// recipient key by.
	KeyIDSize = 8
	// NonceSize is an AES-256-GCM nonce.
	NonceSize = 12
	// TagSize is the AES-256-GCM tag appended to every ciphertext.
	TagSize = 16
)

// The frame types that name their key and AAD, as the wire's lowercase text.
const (
	FrameCall        = "call"
	FrameStreamOpen  = "stream_open"
	FrameResult      = "result"
	FrameError       = "error"
	FrameStreamData  = "stream_data"
	FrameStreamReply = "stream_reply"
	FrameStreamError = "stream_error"
	FrameStreamEnd   = "stream_end"
)

// The labels every derivation and AAD begins with.
const (
	labelPure      = "MACULA-E2E-PURE-V1"
	labelHybrid    = "MACULA-E2E-HYBRID-V1"
	labelCall      = "MACULA-E2E-CALL-V1"
	labelStream    = "MACULA-E2E-STREAM-V1"
	labelEvent     = "MACULA-E2E-EVENT-V1"
	labelAAD       = "MACULA-E2E-AAD-V1"
	labelStreamAAD = "MACULA-E2E-STREAM-AAD-V1"
	labelEventAAD  = "MACULA-E2E-EVENT-AAD-V1"
)

var (
	// ErrRefused is a sealed payload, kem_ct or key that does not open: the
	// wrong length, a point off the curve, a zero ECDH output, or a
	// ciphertext whose key, nonce, AAD or a single bit differs.
	ErrRefused = errors.New("seal: sealed_refused")
	// ErrKey is a recipient key that cannot be built: a profile that is not
	// pq_pure or pq_hybrid, a seed or scalar of the wrong size, or a P-384
	// half where the profile has none, or none where it has one.
	ErrKey = errors.New("seal: not a recipient key")
)

// PublicKey is a recipient's KEM key: the ML-KEM-1024 encapsulation key,
// plus a P-384 point in pq_hybrid.
type PublicKey struct {
	Profile profile.Profile
	MLKEM   *mlkem.EncapsulationKey1024
	P384    *ecdh.PublicKey
}

// PrivateKey is a recipient's KEM key pair: the ML-KEM-1024 decapsulation
// key, plus a P-384 scalar in pq_hybrid.
type PrivateKey struct {
	Profile profile.Profile
	MLKEM   *mlkem.DecapsulationKey1024
	P384    *ecdh.PrivateKey
}

// GenerateKey makes a fresh recipient key in p.
func GenerateKey(p profile.Profile) (*PrivateKey, error) {
	mlkemKey, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	key := &PrivateKey{Profile: p, MLKEM: mlkemKey}
	switch p {
	case profile.PQPure:
		return key, nil
	case profile.PQHybrid:
		key.P384, err = ecdh.P384().GenerateKey(rand.Reader)
		return key, err
	default:
		return nil, fmt.Errorf("%w: profile %q", ErrKey, p)
	}
}

// NewPrivateKey is a recipient key from its ML-KEM-1024 seed (d || z, 64
// bytes) and, in pq_hybrid only, its 48-byte P-384 scalar.
func NewPrivateKey(p profile.Profile, mlkemSeed, p384Scalar []byte) (*PrivateKey, error) {
	hybrid, err := isHybrid(p)
	if err != nil {
		return nil, err
	}
	if hybrid != (p384Scalar != nil) {
		return nil, fmt.Errorf("%w: a %s key with %d bytes of P-384 scalar", ErrKey, p, len(p384Scalar))
	}
	mlkemKey, err := mlkem.NewDecapsulationKey1024(mlkemSeed)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	key := &PrivateKey{Profile: p, MLKEM: mlkemKey}
	if hybrid {
		if key.P384, err = ecdh.P384().NewPrivateKey(p384Scalar); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrKey, err)
		}
	}
	return key, nil
}

func isHybrid(p profile.Profile) (bool, error) {
	switch p {
	case profile.PQPure:
		return false, nil
	case profile.PQHybrid:
		return true, nil
	default:
		return false, fmt.Errorf("%w: profile %q", ErrKey, p)
	}
}

// PublicKey is the recipient key others seal to.
func (k *PrivateKey) PublicKey() *PublicKey {
	pub := &PublicKey{Profile: k.Profile, MLKEM: k.MLKEM.EncapsulationKey()}
	if k.P384 != nil {
		pub.P384 = k.P384.PublicKey()
	}
	return pub
}

// Carried is the key as it is carried and hashed: the ML-KEM key, followed
// by the P-384 point in pq_hybrid.
func (k *PublicKey) Carried() []byte {
	carried := k.MLKEM.Bytes()
	if k.P384 != nil {
		carried = append(carried, k.P384.Bytes()...)
	}
	return carried
}

// KeyHash is the SHA-384 of a key as carried, which the combiner binds.
func KeyHash(carried []byte) [KeyHashSize]byte {
	return sha512.Sum384(carried)
}

// KeyID is the id a sealed payload names its recipient key by: the first 8
// bytes of its key hash.
func KeyID(carried []byte) [KeyIDSize]byte {
	hash := KeyHash(carried)
	return [KeyIDSize]byte(hash[:KeyIDSize])
}

// SenderSecret is a fresh shared secret to recipient, and the kem_ct that
// carries it: ML-KEM-1024's ciphertext, followed by the ephemeral P-384 point
// in pq_hybrid.
func SenderSecret(recipient *PublicKey) ([KeyHashSize]byte, []byte, error) {
	var ephemeral *ecdh.PrivateKey
	if recipient.P384 != nil {
		var err error
		if ephemeral, err = ecdh.P384().GenerateKey(rand.Reader); err != nil {
			return [KeyHashSize]byte{}, nil, err
		}
	}
	return senderSecret(recipient, encapsulate, ephemeral)
}

func encapsulate(ek *mlkem.EncapsulationKey1024) ([]byte, []byte, error) {
	ss, ct := ek.Encapsulate()
	return ss, ct, nil
}

// senderSecret is SenderSecret with its randomness given: an encapsulation
// and the ephemeral P-384 key, which a known-answer test fixes.
func senderSecret(recipient *PublicKey, encaps func(*mlkem.EncapsulationKey1024) ([]byte, []byte, error),
	ephemeral *ecdh.PrivateKey) ([KeyHashSize]byte, []byte, error) {
	ssMLKEM, mlkemCt, err := encaps(recipient.MLKEM)
	if err != nil {
		return [KeyHashSize]byte{}, nil, err
	}
	keyHash := KeyHash(recipient.Carried())
	if recipient.P384 == nil {
		return combine(labelPure, pureIkm(ssMLKEM, mlkemCt, keyHash)), mlkemCt, nil
	}
	ephPub := ephemeral.PublicKey().Bytes()
	ssECDH, err := ecdhSecret(ephemeral, recipient.P384.Bytes())
	if err != nil {
		return [KeyHashSize]byte{}, nil, err
	}
	return combine(labelHybrid, hybridIkm(ssMLKEM, ssECDH, mlkemCt, ephPub, keyHash)),
		append(mlkemCt, ephPub...), nil
}

// RecipientSecret is the shared secret a kem_ct carries, recovered with the
// recipient's own key. A kem_ct of the wrong length for the key's profile, an
// ephemeral point that is not an uncompressed point on P-384, or a zero ECDH
// output is ErrRefused.
func RecipientSecret(recipient *PrivateKey, kemCt []byte) ([KeyHashSize]byte, error) {
	keyHash := KeyHash(recipient.PublicKey().Carried())
	if recipient.P384 == nil {
		if len(kemCt) != MLKEMCiphertextSize {
			return [KeyHashSize]byte{}, ErrRefused
		}
		ssMLKEM, err := recipient.MLKEM.Decapsulate(kemCt)
		if err != nil {
			return [KeyHashSize]byte{}, ErrRefused
		}
		return combine(labelPure, pureIkm(ssMLKEM, kemCt, keyHash)), nil
	}
	if len(kemCt) != MLKEMCiphertextSize+P384PointSize {
		return [KeyHashSize]byte{}, ErrRefused
	}
	mlkemCt, ephPub := kemCt[:MLKEMCiphertextSize], kemCt[MLKEMCiphertextSize:]
	ssECDH, err := ecdhSecret(recipient.P384, ephPub)
	if err != nil {
		return [KeyHashSize]byte{}, err
	}
	ssMLKEM, err := recipient.MLKEM.Decapsulate(mlkemCt)
	if err != nil {
		return [KeyHashSize]byte{}, ErrRefused
	}
	return combine(labelHybrid, hybridIkm(ssMLKEM, ssECDH, mlkemCt, ephPub, keyHash)), nil
}

// ecdhSecret is the 48-byte x coordinate of priv times the peer's point.
// crypto/ecdh takes only an uncompressed point on the curve, and a zero
// output is refused as the spec requires.
func ecdhSecret(priv *ecdh.PrivateKey, peerPoint []byte) ([]byte, error) {
	peer, err := ecdh.P384().NewPublicKey(peerPoint)
	if err != nil {
		return nil, ErrRefused
	}
	secret, err := priv.ECDH(peer)
	if err != nil || subtle.ConstantTimeCompare(secret, make([]byte, len(secret))) == 1 {
		return nil, ErrRefused
	}
	return secret, nil
}

func pureIkm(ssMLKEM, mlkemCt []byte, keyHash [KeyHashSize]byte) []byte {
	return encode(cbor.Bytes(ssMLKEM), cbor.Bytes(mlkemCt), cbor.Bytes(keyHash[:]))
}

func hybridIkm(ssMLKEM, ssECDH, mlkemCt, ephPub []byte, keyHash [KeyHashSize]byte) []byte {
	return encode(cbor.Bytes(ssMLKEM), cbor.Bytes(ssECDH), cbor.Bytes(mlkemCt), cbor.Bytes(ephPub),
		cbor.Bytes(keyHash[:]))
}

// combine is HKDF-Extract with the profile's label as the salt.
func combine(label string, ikm []byte) [KeyHashSize]byte {
	return [KeyHashSize]byte(extract([]byte(label), ikm))
}

// Parties are the request_id, caller and target one call's or stream's keys
// are bound to.
type Parties struct {
	RequestID [16]byte
	Caller    [32]byte
	Target    [32]byte
}

// CallKeys are the request and reply keys of one CALL or STREAM_OPEN.
// frameType is FrameCall or FrameStreamOpen.
func CallKeys(secret [KeyHashSize]byte, frameType string, p Parties) (kReq, kRep [32]byte) {
	okm := expand(secret[:], encode(cbor.Text(labelCall), cbor.Text(frameType), cbor.Bytes(p.RequestID[:]),
		cbor.Bytes(p.Caller[:]), cbor.Bytes(p.Target[:])), 64)
	return [32]byte(okm[:32]), [32]byte(okm[32:])
}

// StreamKeys are the caller-to-provider and provider-to-caller keys of one
// stream.
func StreamKeys(secret [KeyHashSize]byte, p Parties) (kC2P, kP2C [32]byte) {
	okm := expand(secret[:], encode(cbor.Text(labelStream), cbor.Bytes(p.RequestID[:]), cbor.Bytes(p.Caller[:]),
		cbor.Bytes(p.Target[:])), 64)
	return [32]byte(okm[:32]), [32]byte(okm[32:])
}

// EventKey is a publisher's subkey of a group epoch key: every publisher
// seals under its own, so no two ever share a key.
func EventKey(groupKey, publisher [32]byte) [32]byte {
	return [32]byte(expand(eventPRK(groupKey), encode(cbor.Text(labelEvent), cbor.Bytes(publisher[:])), 32))
}

// eventPRK extracts the group key first: it is 32 bytes, and HKDF-Expand
// wants a PRK of the hash's 48.
func eventPRK(groupKey [32]byte) []byte {
	return extract([]byte(labelEvent), groupKey[:])
}

// Request is what a request's sealed payload is bound to: its routing
// fields.
type Request struct {
	FrameType string
	Realm     [32]byte
	Procedure string
	Caller    [32]byte
	Target    [32]byte
	RequestID [16]byte
	Deadline  uint64
}

func (r Request) fields(frameType string) []cbor.Value {
	return []cbor.Value{cbor.Text(labelAAD), cbor.Text(frameType), cbor.Bytes(r.Realm[:]), cbor.Text(r.Procedure),
		cbor.Bytes(r.Caller[:]), cbor.Bytes(r.Target[:]), cbor.Bytes(r.RequestID[:]), cbor.Uint64(r.Deadline)}
}

// RequestAAD is a CALL's or STREAM_OPEN's AAD. Its nonce is 12 zero bytes:
// k_req seals exactly one payload.
func RequestAAD(r Request) []byte {
	return encode(r.fields(r.FrameType)...)
}

// ReplyAAD is a RESULT's or ERROR's AAD: its request's routing fields under
// the reply's frame type, the request hash the reply carries and the
// provider that responded.
func ReplyAAD(r Request, replyFrameType string, requestHash [48]byte, respondedBy [32]byte) []byte {
	return encode(append(r.fields(replyFrameType), cbor.Bytes(requestHash[:]), cbor.Bytes(respondedBy[:]))...)
}

// Direction is which way a stream frame travels.
type Direction uint8

const (
	// CallerToProvider frames seal under k_c2p, with their seq as the nonce.
	CallerToProvider Direction = 0
	// ProviderToCaller frames seal under k_p2c, with a random nonce carried.
	ProviderToCaller Direction = 1
)

// StreamAAD is a stream frame's AAD. A Direction other than the two
// constants is a programming error and panics.
func StreamAAD(frameType string, requestID [16]byte, seq uint64, d Direction) []byte {
	if d != CallerToProvider && d != ProviderToCaller {
		panic(fmt.Sprintf("seal: stream direction %d", d))
	}
	return encode(cbor.Text(labelStreamAAD), cbor.Text(frameType), cbor.Bytes(requestID[:]), cbor.Uint64(seq),
		cbor.Uint64(uint64(d)))
}

// EventAAD is an event's AAD.
func EventAAD(realm [32]byte, topic string, publisher [32]byte, seq, publishedAt uint64) []byte {
	return encode(cbor.Text(labelEventAAD), cbor.Bytes(realm[:]), cbor.Text(topic), cbor.Bytes(publisher[:]),
		cbor.Uint64(seq), cbor.Uint64(publishedAt))
}

// StreamNonce is a caller stream frame's nonce: its seq as a 96-bit
// big-endian integer.
func StreamNonce(seq uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	binary.BigEndian.PutUint64(nonce[4:], seq)
	return nonce
}

// RandomNonce is a fresh nonce, for a reply, a provider stream frame or an
// event, which carry theirs.
func RandomNonce() [NonceSize]byte {
	var nonce [NonceSize]byte
	rand.Read(nonce[:])
	return nonce
}

// Seal is AES-256-GCM: the ciphertext with its 16-byte tag appended.
func Seal(key [32]byte, nonce [NonceSize]byte, aad, plain []byte) []byte {
	return gcm(key).Seal(nil, nonce[:], plain, aad)
}

// Open is the plaintext of a sealed payload, or ErrRefused when the key, the
// nonce, the AAD or a single bit of it differ.
func Open(key [32]byte, nonce [NonceSize]byte, aad, sealed []byte) ([]byte, error) {
	if len(sealed) < TagSize {
		return nil, ErrRefused
	}
	plain, err := gcm(key).Open(nil, nonce[:], sealed, aad)
	if err != nil {
		return nil, ErrRefused
	}
	return plain, nil
}

func gcm(key [32]byte) cipher.AEAD {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		panic(err) // a 32-byte key is always an AES-256 key
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err) // AES has GCM's 16-byte block
	}
	return aead
}

// HKDF-SHA-384 (RFC 5869). Neither call can fail here: every secret and PRK
// is at least 32 bytes and no output is over 255 blocks.

func extract(salt, ikm []byte) []byte {
	prk, err := hkdf.Extract(sha512.New384, ikm, salt)
	if err != nil {
		panic(err)
	}
	return prk
}

func expand(prk, info []byte, length int) []byte {
	okm, err := hkdf.Expand(sha512.New384, prk, string(info), length)
	if err != nil {
		panic(err)
	}
	return okm
}

// encode is the CBOR array of the items in cbor's deterministic encoding,
// which for arrays of byte strings, text and unsigned integers is RFC 8949's
// core deterministic one.
func encode(items ...cbor.Value) []byte {
	return cbor.Encode(cbor.List(items))
}
