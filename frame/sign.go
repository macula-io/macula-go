package frame

import (
	"errors"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// Sign signs frame with identity, over SigDomain || canonical_cbor(frame
// minus signature/publisher_sig), and returns the frame with its
// signature field set (64 bytes).
func Sign(frameVal cbor.Value, id identity.KeyPair) cbor.Value {
	signable := signableBytes(frameVal)
	sig := id.Sign(signable)
	return withFieldOnValue(frameVal, "signature", cbor.Bytes(sig))
}

func signableBytes(frameVal cbor.Value) []byte {
	unsigned := without(frameVal, "signature", "publisher_sig")
	canonical := cbor.Encode(unsigned)
	out := make([]byte, 0, len(SigDomain)+len(canonical))
	out = append(out, []byte(SigDomain)...)
	out = append(out, canonical...)
	return out
}

// ErrMissingSignature, ErrBadSignature, and ErrSignatureInvalid are the
// error classes Verify can return.
var (
	ErrMissingSignature = errors.New("frame has no signature field")
	ErrBadSignature     = errors.New("signature field is not 64 bytes")
	ErrSignatureInvalid = errors.New("signature does not verify against pubkey")
)

// Verify checks frame's signature field against pubkey, over the same
// domain-separated bytes Sign produces.
func Verify(frameVal cbor.Value, pubkey []byte) error {
	sigVal, ok := frameVal.Get("signature")
	if !ok {
		return ErrMissingSignature
	}
	sig, ok := sigVal.AsBytes()
	if !ok || len(sig) != 64 {
		return ErrBadSignature
	}
	signable := signableBytes(frameVal)
	if identity.Verify(pubkey, signable, sig) {
		return nil
	}
	return ErrSignatureInvalid
}

// without returns a copy of v (which must be a KindMap) with the given
// keys removed.
func without(v cbor.Value, keys ...string) cbor.Value {
	entries, ok := v.AsMap()
	if !ok {
		return v
	}
	skip := make(map[string]bool, len(keys))
	for _, k := range keys {
		skip[k] = true
	}
	out := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		if t, ok := e.Key.AsText(); ok && skip[t] {
			continue
		}
		out = append(out, e)
	}
	return cbor.Map(out)
}

// withFieldOnValue is withField (envelope.go) for an already-built
// cbor.Value map, used to attach `signature` after the fact.
func withFieldOnValue(v cbor.Value, key string, val cbor.Value) cbor.Value {
	entries, ok := v.AsMap()
	if !ok {
		return v
	}
	return cbor.Map(withField(entries, key, val))
}
