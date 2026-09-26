package frame

import (
	"bytes"
	"errors"

	"github.com/macula-io/macula-go/cbor"
)

// Sealed is a payload sealed end to end (macula 13, E2E seal scheme 1,
// seal/testdata/E2E_SEAL_V1.md "The sealed map"): the recipient key's id, the
// ciphertext with its tag, and, by the frame it rides in, a request's kem_ct
// (it agrees the keys; its nonce is fixed) or a reply's, an event's or a
// provider stream frame's carried nonce. A caller stream frame's nonce is its
// seq, so it carries neither. A frame carries Sealed in place of its clear
// field, never beside it. This package opens nothing: package seal does.
type Sealed struct {
	KeyID [8]byte
	KemCt []byte
	Nonce []byte
	Ct    []byte
}

// SealedScheme is the only scheme a sealed map may name.
const SealedScheme = 1

// ErrSealedShape is a sealed payload built with another shape than its frame's:
// a request's without a kem_ct of a profile's size or with a nonce, a reply's
// or a provider stream frame's without a 12-byte nonce or with a kem_ct, or a
// caller stream frame's with either.
var ErrSealedShape = errors.New("frame: a sealed payload of another shape than its frame's")

// sealedContext is the frame a sealed map rides in, which sets its shape.
type sealedContext int

const (
	sealedRequest sealedContext = iota
	sealedReply
	sealedEvent
	sealedProviderStream
	sealedCallerStream
)

// kemCtSizes are a request's kem_ct sizes: an ML-KEM-1024 ciphertext, followed
// in pq_hybrid by an uncompressed P-384 point.
const (
	kemCtPureSize   = 1568
	kemCtHybridSize = 1665
	sealedNonceSize = 12
)

// value is the sealed map as it travels.
func (s Sealed) value() cbor.Value {
	entries := []cbor.MapEntry{
		uintEntry("scheme", SealedScheme),
		bytesEntry("key_id", s.KeyID[:]),
		bytesEntry("ct", s.Ct),
	}
	if s.KemCt != nil {
		entries = append(entries, bytesEntry("kem_ct", s.KemCt))
	}
	if s.Nonce != nil {
		entries = append(entries, bytesEntry("nonce", s.Nonce))
	}
	return cbor.Map(entries)
}

// shaped reports whether s has the shape its frame's context requires, as
// macula_frame's sealed_shape/3 holds it.
func (s Sealed) shaped(context sealedContext) bool {
	hasKemCt, hasNonce := s.KemCt != nil, s.Nonce != nil
	if hasNonce && len(s.Nonce) != sealedNonceSize {
		return false
	}
	switch context {
	case sealedRequest:
		return hasKemCt && !hasNonce && (len(s.KemCt) == kemCtPureSize || len(s.KemCt) == kemCtHybridSize)
	case sealedReply, sealedEvent, sealedProviderStream:
		return !hasKemCt && hasNonce
	case sealedCallerStream:
		return !hasKemCt && !hasNonce
	}
	return false
}

// sealedTable is a sealed map's fields: exactly these, as sealed_table/0 names
// them.
var sealedTable = map[string]fieldRule{
	"scheme": protocolUint,
	"key_id": bytesOf(8),
	"kem_ct": anyBytes,
	"nonce":  bytesOf(sealedNonceSize),
	"ct":     anyBytes,
}

// readSealed reads a sealed map as a verifier reads it, opening nothing:
// scheme 1, a key id and a ciphertext, and the shape its frame's context
// requires. Any other map, or a key the table cannot name, is not one.
func readSealed(v cbor.Value, context sealedContext) (Sealed, bool) {
	fields, ok := readFields(v, sealedTable)
	if !ok || !hasFields(fields, "scheme", "key_id", "ct") {
		return Sealed{}, false
	}
	if scheme, _ := fields["scheme"].AsInt64(); scheme != SealedScheme {
		return Sealed{}, false
	}
	var s Sealed
	fixedBytes(s.KeyID[:], fields["key_id"])
	ct, _ := fields["ct"].AsBytes()
	s.Ct = bytes.Clone(ct)
	if kemCt, has := fields["kem_ct"]; has {
		b, _ := kemCt.AsBytes()
		s.KemCt = bytes.Clone(b)
	}
	if nonce, has := fields["nonce"]; has {
		b, _ := nonce.AsBytes()
		s.Nonce = bytes.Clone(b)
	}
	return s, s.shaped(context)
}

// sealedRule is a field rule for a sealed map in context.
func sealedRule(context sealedContext) fieldRule {
	return func(v cbor.Value) bool {
		_, ok := readSealed(v, context)
		return ok
	}
}

// payloadOrSealed reports whether fields carry a payload in the clear or
// sealed, exactly one of the two (macula_frame's payload_or_sealed/1).
func payloadOrSealed(fields map[string]cbor.Value) bool {
	_, hasPayload := fields["payload"]
	_, hasSealed := fields["sealed"]
	return hasPayload != hasSealed
}

// sealedField is the sealed map a frame's fields carry, nil for none; the
// fields have been read against a table holding sealedRule, so it reads.
func sealedField(fields map[string]cbor.Value, context sealedContext) *Sealed {
	v, has := fields["sealed"]
	if !has {
		return nil
	}
	s, _ := readSealed(v, context)
	return &s
}
