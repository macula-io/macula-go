package identity

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// The refusals of a signed object, named as macula_signed_object names them.
var (
	// ErrObjectMalformed is a signed object without exactly the keys of its
	// shape, each a byte string; a carried key not in the verifier's profile's
	// carried form; or a tbs the decoding rule refuses, or that is not a map
	// naming alg as text.
	ErrObjectMalformed = errors.New("identity: malformed signed object")
	// ErrObjectSignatureInvalid is a signed object whose signature does not
	// verify over its label, its key's hash and its tbs as received.
	ErrObjectSignatureInvalid = errors.New("identity: the signed object's signature does not verify")
	// ErrObjectAlgMismatch is a signed object whose alg names another profile's
	// algorithm than the verifier's.
	ErrObjectAlgMismatch = errors.New("identity: the signed object names another profile's algorithm")
)

// Object is a signed object that carries its signer's key as carried: a
// record, a request, a reply, a relay error, a publication, or a provider's
// first frame on a stream.
type Object struct {
	Key       []byte
	TBS       []byte
	Signature []byte
}

// HeldObject is a signed object whose verifier already holds the signer's key:
// a provider's later frames on a stream, a caller's stream frames, and a
// neighbour signature. Its signature still covers the key's hash.
type HeldObject struct {
	TBS       []byte
	Signature []byte
}

// VerifiedObject is a signed object that verified: copies of the key it
// verified with and of its tbs bytes as received, and the map they decode to.
// Nothing a caller later writes into the bytes it verified changes them.
type VerifiedObject struct {
	Key    []byte
	TBS    []byte
	Fields cbor.Value
}

// SignObject signs fields under label with key, as macula_signed_object:sign/3
// does. The fields gain alg, the name of key's profile algorithm, replacing any
// alg they held, and are encoded as tbs in the deterministic form. The
// signature covers label, a zero byte, the SHA-384 of key as carried, and tbs.
// Every field needs a text key of its own.
func SignObject(label string, fields []cbor.MapEntry, key *NodeKey) (Object, error) {
	carried := key.PublicKey()
	if carried == nil {
		return Object{}, ErrEmptyNodeKey
	}
	tbs, err := objectTBS(fields, key.profile)
	if err != nil {
		return Object{}, err
	}
	signature, err := key.Sign(objectSignedBytes(label, carried, tbs))
	if err != nil {
		return Object{}, err
	}
	return Object{Key: carried, TBS: tbs, Signature: signature}, nil
}

// SignHeldObject is SignObject for a verifier that already holds key: the
// object leaves the key out, and its signature still covers the key's hash.
func SignHeldObject(label string, fields []cbor.MapEntry, key *NodeKey) (HeldObject, error) {
	object, err := SignObject(label, fields, key)
	if err != nil {
		return HeldObject{}, err
	}
	return HeldObject{TBS: object.TBS, Signature: object.Signature}, nil
}

// VerifyObject verifies a signed object that carries its key, under label and
// the verifier's profile p, reading it in macula's order: exactly the keys key,
// tbs and signature, each a byte string; key in p's carried form; the
// signature over tbs as received; only then tbs under the decoding rule, a map
// whose alg names p's algorithm. alg is checked and never selects an algorithm.
func VerifyObject(label string, v cbor.Value, p profile.Profile) (VerifiedObject, error) {
	object, err := ParseObject(v)
	if err != nil {
		return VerifiedObject{}, err
	}
	if !CarriedKeyWellFormed(object.Key, p) {
		return VerifiedObject{}, ErrObjectMalformed
	}
	return verifiedObject(label, object.Key, object.TBS, object.Signature, p)
}

// VerifyHeldObject verifies a signed object whose key the verifier holds, under
// label, that key as carried and the verifier's profile p: exactly the keys tbs
// and signature, each a byte string, then the signature, tbs and alg as
// VerifyObject reads them.
func VerifyHeldObject(label string, v cbor.Value, key []byte, p profile.Profile) (VerifiedObject, error) {
	held, err := ParseHeldObject(v)
	if err != nil {
		return VerifiedObject{}, err
	}
	return verifiedObject(label, key, held.TBS, held.Signature, p)
}

// Value is o as the map {key, tbs, signature}.
func (o Object) Value() cbor.Value {
	return cbor.Map([]cbor.MapEntry{bytesEntry("key", o.Key), bytesEntry("tbs", o.TBS), bytesEntry("signature", o.Signature)})
}

// Value is o as the map {tbs, signature}.
func (o HeldObject) Value() cbor.Value {
	return cbor.Map([]cbor.MapEntry{bytesEntry("tbs", o.TBS), bytesEntry("signature", o.Signature)})
}

// ParseObject reads a signed object that carries its key from v, which must be
// a map of exactly key, tbs and signature, each a byte string, or
// ErrObjectMalformed.
func ParseObject(v cbor.Value) (Object, error) {
	values, ok := exactByteFields(v, "key", "tbs", "signature")
	if !ok {
		return Object{}, ErrObjectMalformed
	}
	return Object{Key: values[0], TBS: values[1], Signature: values[2]}, nil
}

// ParseHeldObject reads a signed object whose key the verifier holds from v,
// which must be a map of exactly tbs and signature, each a byte string, or
// ErrObjectMalformed.
func ParseHeldObject(v cbor.Value) (HeldObject, error) {
	values, ok := exactByteFields(v, "tbs", "signature")
	if !ok {
		return HeldObject{}, ErrObjectMalformed
	}
	return HeldObject{TBS: values[0], Signature: values[1]}, nil
}

// DecodeObject reads a signed object that carries its key from its CBOR bytes,
// under the decoding rule.
func DecodeObject(b []byte) (Object, error) {
	v, err := cbor.Decode(b)
	if err != nil {
		return Object{}, fmt.Errorf("%w: %w", ErrObjectMalformed, err)
	}
	return ParseObject(v)
}

// DecodeHeldObject reads a signed object whose key the verifier holds from its
// CBOR bytes, under the decoding rule.
func DecodeHeldObject(b []byte) (HeldObject, error) {
	v, err := cbor.Decode(b)
	if err != nil {
		return HeldObject{}, fmt.Errorf("%w: %w", ErrObjectMalformed, err)
	}
	return ParseHeldObject(v)
}

// objectTBS is fields with alg for profile p, in the deterministic encoding. A
// field without a text key, or two fields with one key, is refused.
func objectTBS(fields []cbor.MapEntry, p profile.Profile) ([]byte, error) {
	definition, err := p.Definition()
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(fields)+1)
	withAlg := make([]cbor.MapEntry, 0, len(fields)+1)
	for _, e := range fields {
		name, isText := e.Key.AsText()
		switch {
		case !isText:
			return nil, fmt.Errorf("identity: sign object: a field key that is not text: %v", e.Key)
		case seen[name]:
			return nil, fmt.Errorf("identity: sign object: two fields named %q", name)
		case name == "alg":
			continue
		}
		seen[name] = true
		withAlg = append(withAlg, e)
	}
	withAlg = append(withAlg, textEntry("alg", definition.SigAlg))
	return cbor.Encode(cbor.Map(withAlg)), nil
}

// objectSignedBytes is what a signed object's signature covers: label, a zero
// byte, the SHA-384 of the key as carried, and tbs.
func objectSignedBytes(label string, key, tbs []byte) []byte {
	keyHash := sha512.Sum384(key)
	out := make([]byte, 0, len(label)+1+len(keyHash)+len(tbs))
	out = append(out, label...)
	out = append(out, 0)
	out = append(out, keyHash[:]...)
	return append(out, tbs...)
}

// verifiedObject checks the signature over tbs as received, then decodes tbs
// and checks its alg against profile p. The result holds copies of key and tbs,
// since both may be a caller's own buffers.
func verifiedObject(label string, key, tbs, signature []byte, p profile.Profile) (VerifiedObject, error) {
	if err := verifySignature(objectSignedBytes(label, key, tbs), signature, key, p, ErrObjectSignatureInvalid); err != nil {
		return VerifiedObject{}, err
	}
	fields, err := cbor.Decode(tbs)
	if err != nil {
		return VerifiedObject{}, fmt.Errorf("%w: %w", ErrObjectMalformed, err)
	}
	alg, hasAlg := fields.Get("alg")
	name, isText := alg.AsText()
	if _, isMap := fields.AsMap(); !isMap || !hasAlg || !isText {
		return VerifiedObject{}, ErrObjectMalformed
	}
	if name != sigAlg(p) {
		return VerifiedObject{}, ErrObjectAlgMismatch
	}
	return VerifiedObject{Key: bytes.Clone(key), TBS: bytes.Clone(tbs), Fields: fields}, nil
}

// exactByteFields is the byte strings under names in v, when v is a map of
// exactly those text keys, each holding a byte string.
func exactByteFields(v cbor.Value, names ...string) ([][]byte, bool) {
	entries, isMap := v.AsMap()
	if !isMap || len(entries) != len(names) {
		return nil, false
	}
	values := make([][]byte, len(names))
	for i, name := range names {
		b, ok := fieldBytes(v, name)
		if !ok {
			return nil, false
		}
		values[i] = b
	}
	return values, true
}
