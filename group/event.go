package group

import (
	"crypto/rand"
	"errors"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/seal"
)

// Fields are what an event's seal is bound to: the publication's routing
// fields, which the event AAD covers.
type Fields struct {
	Realm       [32]byte
	Topic       string
	Publisher   [32]byte
	Seq         uint64
	PublishedAt uint64
}

// ErrTagInvalid is an event that does not open under the epoch it names:
// another epoch's key, a routing field other than the one it was sealed with,
// or a changed byte.
var ErrTagInvalid = errors.New("group: the sealed event does not open (tag_invalid)")

// SealEvent seals payload for a publication with f under epoch, as
// macula_group_event:seal/3 does: under the publisher's own subkey of the
// epoch key, k_pub, with a fresh 96-bit random nonce, bound by the event AAD
// to f. The plaintext is the payload's deterministic CBOR. The result rides
// in the PUBLISH in place of payload.
func SealEvent(epoch Epoch, f Fields, payload cbor.Value) (frame.Sealed, error) {
	if err := frame.CheckPayload(payload); err != nil {
		return frame.Sealed{}, err
	}
	var nonce [seal.NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return frame.Sealed{}, err
	}
	key := seal.EventKey(epoch.Key, f.Publisher)
	ct := seal.Seal(key, nonce, aad(f), cbor.Encode(payload))
	return frame.Sealed{Scheme: frame.SealedScheme, KeyID: epoch.ID, Nonce: nonce[:], Ct: ct}, nil
}

// OpenEvent opens a sealed event with f under epoch, as
// macula_group_event:open/2 does, and returns its payload in the shape a
// clear payload arrives in, or ErrTagInvalid.
func OpenEvent(epoch Epoch, f Fields, sealed frame.Sealed) (cbor.Value, error) {
	if !sealed.KnownScheme() || len(sealed.Nonce) != seal.NonceSize {
		return cbor.Value{}, ErrTagInvalid
	}
	key := seal.EventKey(epoch.Key, f.Publisher)
	plain, err := seal.Open(key, [seal.NonceSize]byte(sealed.Nonce), aad(f), sealed.Ct)
	if err != nil {
		return cbor.Value{}, ErrTagInvalid
	}
	payload, err := cbor.Decode(plain)
	if err != nil {
		return cbor.Value{}, ErrTagInvalid
	}
	return payload, nil
}

func aad(f Fields) []byte {
	return seal.EventAAD(f.Realm, f.Topic, f.Publisher, f.Seq, f.PublishedAt)
}
