package frame

import (
	"errors"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// EventPublisherDomain is the domain separator for `publisher_sig`, the
// separate end-to-end signature on PUBLISH/EVENT frames (Erlang
// macula_frame.erl's ?EVENT_PUBLISHER_DOMAIN, plans/PLAN_WIRE_PROTOCOL.md
// §6.6). Distinct from SigDomain: SigDomain covers a frame's own,
// per-hop `signature`, which is verified against the CONNECTION a frame
// arrived on and is therefore only valid for the immediate sender.
// `publisher_sig` covers just (topic, realm, publisher, seq, payload),
// independent of frame type, so it survives PUBLISH -> EVENT conversion
// and every relay hop -- a receiving station or client can verify
// authenticity against the ORIGINAL publisher no matter how many
// stations forwarded it.
const EventPublisherDomain = "macula-v2-event-pub\x00"

// SignPublisher adds `publisher_sig' to a PUBLISH or EVENT frame: id's
// Ed25519 signature over (topic, realm, publisher, seq, payload). id
// must be the key pair for the pubkey already in the frame's
// `publisher' field -- SignPublisher does not check this (callers
// build frames with their own identity's pubkey as `publisher' by
// construction; see connection.Session.Publish).
func SignPublisher(frameVal cbor.Value, id identity.KeyPair) cbor.Value {
	signable := publisherSigningBytes(frameVal)
	sig := id.Sign(signable)
	return withFieldOnValue(frameVal, "publisher_sig", cbor.Bytes(sig))
}

// ErrMissingPublisherSig, ErrBadPublisherSig, and ErrPublisherSigInvalid
// are the error classes VerifyPublisher can return. A caller that
// requires end-to-end authenticity MUST treat ErrMissingPublisherSig as
// a verification failure, not as "trusted" -- see the Erlang reference's
// own verify_publisher/1 doc.
var (
	ErrMissingPublisherSig = errors.New("frame has no publisher_sig field")
	ErrBadPublisherSig     = errors.New("publisher_sig field is not 64 bytes")
	ErrPublisherSigInvalid = errors.New("publisher_sig does not verify against the frame's publisher field")
)

// VerifyPublisher checks a frame's `publisher_sig' against its OWN
// `publisher' field -- unlike Verify (the per-hop signature), there is
// no separate pubkey parameter: publisher_sig's whole point is proving
// "the pubkey named in this frame produced it", independent of which
// connection it arrived on.
func VerifyPublisher(frameVal cbor.Value) error {
	sigVal, ok := frameVal.Get("publisher_sig")
	if !ok {
		return ErrMissingPublisherSig
	}
	sig, ok := sigVal.AsBytes()
	if !ok || len(sig) != 64 {
		return ErrBadPublisherSig
	}
	pubVal, ok := frameVal.Get("publisher")
	if !ok {
		return ErrBadPublisherSig
	}
	pub, ok := pubVal.AsBytes()
	if !ok || len(pub) != 32 {
		return ErrBadPublisherSig
	}
	signable := publisherSigningBytes(frameVal)
	if identity.Verify(pub, signable, sig) {
		return nil
	}
	return ErrPublisherSigInvalid
}

// publisherSigningBytes builds the canonical bytes a publisher signs: a
// fixed 5-field tuple, independent of frame type, header fields,
// `delivered_via', or `ttl_ms', so the same signature is valid on the
// PUBLISH the publisher sent and on every EVENT a relay derives from it.
func publisherSigningBytes(frameVal cbor.Value) []byte {
	fields := []string{"topic", "realm", "publisher", "seq", "payload"}
	entries := make([]cbor.MapEntry, 0, len(fields))
	for _, f := range fields {
		val, ok := frameVal.Get(f)
		if !ok {
			val = cbor.Null()
		}
		entries = append(entries, cbor.MapEntry{Key: cbor.Text(f), Val: val})
	}
	canonical := cbor.Encode(cbor.Map(entries))
	out := make([]byte, 0, len(EventPublisherDomain)+len(canonical))
	out = append(out, []byte(EventPublisherDomain)...)
	out = append(out, canonical...)
	return out
}
