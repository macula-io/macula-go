// Package ownershipproof signs and verifies an ownership proof v2
// (mcl-om#7): the asserted_by block a payload carries to show that an
// identity authorised exactly this request, in this realm, once. It binds
// every field of the payload the handler receives, the procedure, the realm,
// a timestamp and a nonce, under its own tag, so a relay cannot change a
// field, move the proof to another procedure or realm, or send it twice.
//
// The signed bytes are mcl_om 0.32.0's mcl_om_ownership_proof:message/6,
// byte for byte: deterministic CBOR of a map of eight text-keyed entries.
// testdata/vector holds that module's own output for fixed inputs, with a
// signature an Erlang key made over it.
//
// The block goes in the payload beside the fields it authorises:
//
//	asserted_by: {identity: <node_id hex>,
//	              proof: {v: 2, timestamp: <ms>, nonce: <hex>,
//	                      signature: <hex>, public: <carried key hex>}}
//
// The fields are the payload minus asserted_by and minus a text "caller": a
// macula station link removes a caller-sent caller before the handler reads
// the payload, and merges in the caller it authenticated, which a Go provider
// reads as stationlink.Request.Caller (macula_station_link:with_caller/2).
// Neither is signed, and a signer refuses a payload carrying a caller
// (ErrCallerField) rather than send a field no handler reads. Verify leaves replay to its caller: it returns the
// identity and nonce, which a verifier accepts once (mcl_om keeps each nonce
// for 120 s after acceptance, beyond the 60 s skew either side).
package ownershipproof

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const (
	// Tag names what the signature is for, so it signs nothing else.
	Tag = "macula.ownership_proof"
	// Version is the proof's version, 2; a verifier refuses any other.
	Version = 2
	// NonceSize is the nonce's length in bytes.
	NonceSize = 16
	// Field is the payload key the block goes under.
	Field = "asserted_by"
	// callerField is the key a station link replaces with the authenticated
	// caller before a handler reads the payload.
	callerField = "caller"
	// MaxSkew is how far a proof's timestamp may be from the verifier's clock.
	MaxSkew = 60 * time.Second
)

var (
	// ErrMissingProof is a payload without a usable asserted_by block, or a
	// proof without a timestamp (mcl_om's missing_proof).
	ErrMissingProof = errors.New("ownershipproof: no ownership proof")
	// ErrUnsupportedVersion is a proof whose v is not 2.
	ErrUnsupportedVersion = errors.New("ownershipproof: unsupported proof version")
	// ErrStaleProof is a timestamp more than MaxSkew from now.
	ErrStaleProof = errors.New("ownershipproof: stale proof")
	// ErrBadSignature is a signature that does not verify, or a carried key
	// that does not derive the identity.
	ErrBadSignature = errors.New("ownershipproof: bad signature")
	// ErrInvalidIdentity is an identity that is not 32 bytes, as 64 hex
	// characters or raw.
	ErrInvalidIdentity = errors.New("ownershipproof: invalid identity")
	// ErrNotAMap is a payload that is not a map, so it has no fields to bind.
	ErrNotAMap = errors.New("ownershipproof: the payload is not a map")
	// ErrCallerField is a payload to sign carrying a text "caller": a station
	// link replaces it with the caller it authenticated before any handler
	// reads it, so it can be neither sent nor signed.
	ErrCallerField = errors.New(`ownershipproof: a payload carries "caller", which a station replaces; leave it out`)
)

// Proof is the proof as it goes on the wire, every byte string as hex.
type Proof struct {
	V         int
	Timestamp uint64
	Nonce     string
	Signature string
	// Public is the signer's carried public key; the identity must derive
	// from it.
	Public string
}

// AssertedBy is the block a payload carries under Field.
type AssertedBy struct {
	// Identity is the signer's node_id, hex.
	Identity string
	Proof    Proof
}

// Value is the block as the payload carries it: a map with text keys.
func (a AssertedBy) Value() cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("identity"), Val: cbor.Text(a.Identity)},
		{Key: cbor.Text("proof"), Val: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("v"), Val: cbor.Int(int64(a.Proof.V))},
			{Key: cbor.Text("timestamp"), Val: cbor.Uint64(a.Proof.Timestamp)},
			{Key: cbor.Text("nonce"), Val: cbor.Text(a.Proof.Nonce)},
			{Key: cbor.Text("signature"), Val: cbor.Text(a.Proof.Signature)},
			{Key: cbor.Text("public"), Val: cbor.Text(a.Proof.Public)},
		})},
	})
}

// Verified is who a verified proof says authorised the payload, and the
// nonce to record so the same proof is accepted once.
type Verified struct {
	Identity [32]byte
	Nonce    [NonceSize]byte
}

// Message is the exact bytes an identity signs: its node_id, the realm id,
// the procedure, the timestamp in milliseconds, the nonce and the fields,
// under the tag and version.
func Message(id [32]byte, realm [32]byte, procedure string, timestampMs uint64, nonce [NonceSize]byte,
	fields cbor.Value) []byte {
	return cbor.Encode(cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("tag"), Val: cbor.Text(Tag)},
		{Key: cbor.Text("v"), Val: cbor.Uint64(Version)},
		{Key: cbor.Text("identity"), Val: cbor.Bytes(id[:])},
		{Key: cbor.Text("realm"), Val: cbor.Bytes(realm[:])},
		{Key: cbor.Text("procedure"), Val: cbor.Text(procedure)},
		{Key: cbor.Text("timestamp"), Val: cbor.Uint64(timestampMs)},
		{Key: cbor.Text("nonce"), Val: cbor.Bytes(nonce[:])},
		{Key: cbor.Text("fields"), Val: fields},
	}))
}

// Sign signs the fields of payload (Fields) for procedure in realm as key's
// node, now and with a fresh nonce. payload is the payload as it goes on the
// wire: a map, without a text "caller" (ErrCallerField).
func Sign(key *identity.NodeKey, realm [32]byte, procedure string, payload cbor.Value) (AssertedBy, error) {
	if _, hasCaller := payload.Get(callerField); hasCaller {
		return AssertedBy{}, ErrCallerField
	}
	fields, err := Fields(payload)
	if err != nil {
		return AssertedBy{}, err
	}
	var nonce [NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return AssertedBy{}, err
	}
	return signAt(key, realm, procedure, fields, uint64(time.Now().UnixMilli()), nonce)
}

func signAt(key *identity.NodeKey, realm [32]byte, procedure string, fields cbor.Value, timestampMs uint64,
	nonce [NonceSize]byte) (AssertedBy, error) {
	id, err := key.NodeID()
	if err != nil {
		return AssertedBy{}, err
	}
	signature, err := key.Sign(Message(id, realm, procedure, timestampMs, nonce, fields))
	if err != nil {
		return AssertedBy{}, err
	}
	return AssertedBy{
		Identity: hex.EncodeToString(id[:]),
		Proof: Proof{V: Version, Timestamp: timestampMs, Nonce: hex.EncodeToString(nonce[:]),
			Signature: hex.EncodeToString(signature), Public: hex.EncodeToString(key.PublicKey())},
	}, nil
}

// Attach signs payload (a map) for procedure in realm as key's node and
// returns it with its asserted_by block, replacing any earlier one.
// A payload carrying a text "caller" is refused (ErrCallerField).
func Attach(payload cbor.Value, key *identity.NodeKey, realm [32]byte, procedure string) (cbor.Value, error) {
	block, err := Sign(key, realm, procedure, payload)
	if err != nil {
		return cbor.Value{}, err
	}
	entries, _ := payload.AsMap()
	out := make([]cbor.MapEntry, 0, len(entries)+1)
	for _, e := range entries {
		if k, isText := e.Key.AsText(); !isText || k != Field {
			out = append(out, e)
		}
	}
	return cbor.Map(append(out, cbor.MapEntry{Key: cbor.Text(Field), Val: block.Value()})), nil
}

// Fields is what a proof over payload signs: payload minus its asserted_by
// and minus a text "caller", the fields a handler reads that the sender
// chose. payload must be a map.
func Fields(payload cbor.Value) (cbor.Value, error) {
	entries, ok := payload.AsMap()
	if !ok {
		return cbor.Value{}, ErrNotAMap
	}
	fields := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		if k, isText := e.Key.AsText(); isText && (k == Field || k == callerField) {
			continue
		}
		fields = append(fields, e)
	}
	return cbor.Map(fields), nil
}

// Verify checks that payload's asserted_by block shows its identity
// authorised the payload's Fields for procedure in realm, at a timestamp
// within MaxSkew of now, with a key of profile p. payload is as a handler
// receives it. It takes mcl_om_ownership_proof:verify/5's steps in its order
// and gives its refusal for each. It does not guard replay: record the
// returned nonce and refuse one seen before.
func Verify(payload cbor.Value, procedure string, realm [32]byte, p profile.Profile, now time.Time) (Verified, error) {
	fields, err := Fields(payload)
	if err != nil {
		return Verified{}, ErrMissingProof
	}
	block, ok := payload.Get(Field)
	if !ok {
		return Verified{}, ErrMissingProof
	}
	if _, isMap := block.AsMap(); !isMap {
		return Verified{}, ErrMissingProof
	}
	id, ok := decodeIdentity(block)
	if !ok {
		return Verified{}, ErrInvalidIdentity
	}
	proof, ok := block.Get("proof")
	if _, isMap := proof.AsMap(); !ok || !isMap {
		return Verified{}, ErrMissingProof
	}
	if v, ok := proof.Get("v"); !ok || !isInt(v, Version) {
		return Verified{}, ErrUnsupportedVersion
	}
	tsValue, ok := proof.Get("timestamp")
	if !ok {
		return Verified{}, ErrMissingProof
	}
	ts, ok := tsValue.AsInt64()
	if !ok {
		return Verified{}, ErrMissingProof
	}
	if skew := now.UnixMilli() - ts; skew > MaxSkew.Milliseconds() || skew < -MaxSkew.Milliseconds() {
		return Verified{}, ErrStaleProof
	}
	nonceBytes, okNonce := hexField(proof, "nonce")
	signature, okSig := hexField(proof, "signature")
	public, okPub := hexField(proof, "public")
	if !okNonce || !okSig || !okPub || len(nonceBytes) != NonceSize {
		return Verified{}, ErrBadSignature
	}
	// The identity must derive from the carried key before the signature is
	// spent on it.
	if !identity.CarriedKeyWellFormed(public, p) || identity.NodeIDOf(public, p) != id {
		return Verified{}, ErrBadSignature
	}
	var nonce [NonceSize]byte
	copy(nonce[:], nonceBytes)
	if !identity.Verify(Message(id, realm, procedure, uint64(ts), nonce, fields), signature, public, p) {
		return Verified{}, ErrBadSignature
	}
	return Verified{Identity: id, Nonce: nonce}, nil
}

func isInt(v cbor.Value, want int64) bool {
	i, ok := v.AsInt64()
	return ok && i == want
}

// wireString is a text or byte-string value's bytes, as mcl_om_wire reads
// either.
func wireString(v cbor.Value) ([]byte, bool) {
	if s, ok := v.AsText(); ok {
		return []byte(s), true
	}
	return v.AsBytes()
}

// decodeIdentity reads the block's identity: 64 hex characters, or 32 raw
// bytes, as mcl_om_ownership_proof:decode_identity/1 does.
func decodeIdentity(block cbor.Value) ([32]byte, bool) {
	var id [32]byte
	v, ok := block.Get("identity")
	if !ok {
		return id, false
	}
	raw, ok := wireString(v)
	if !ok {
		return id, false
	}
	switch len(raw) {
	case 64:
		decoded, err := hex.DecodeString(string(raw))
		if err != nil {
			return id, false
		}
		copy(id[:], decoded)
		return id, true
	case 32:
		copy(id[:], raw)
		return id, true
	}
	return id, false
}

func hexField(proof cbor.Value, name string) ([]byte, bool) {
	v, ok := proof.Get(name)
	if !ok {
		return nil, false
	}
	raw, ok := wireString(v)
	if !ok {
		return nil, false
	}
	b, err := hex.DecodeString(string(raw))
	return b, err == nil
}
