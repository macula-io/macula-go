package stationlink

import (
	"encoding/hex"
	"errors"
	"slices"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/seal"
)

// End-to-end payload confidentiality, as macula 13 has it (E2E design §5,
// §8, amendment A1; seal scheme 1). A provider that names its KEM key in its
// advertisement opens the requests sealed to it and seals every answer to
// them. What it cannot open it refuses in the clear, from a closed set that
// carries no application data. A caller seals to the key a verified
// advertisement names, never falls back to the clear, and takes a clear
// answer to a sealed request only from that closed set or as a relay error.

// Confidentiality is how a procedure takes its requests.
type Confidentiality int

const (
	// ConfidentialPreferred, the default: with kem_advertise on, the
	// advertisement names the key and callers seal to it; a clear request is
	// still taken while the procedure's last keyless advertisement could be
	// served, then refused sealed_required.
	ConfidentialPreferred Confidentiality = iota
	// ConfidentialRequired names the key and refuses every clear request.
	// It needs kem_advertise on: a provider that names no key and refuses
	// every clear call is unreachable.
	ConfidentialRequired
	// ConfidentialOff names no key: the procedure is served in the clear.
	ConfidentialOff
)

// The clear codes of a sealed request's refusals.
const (
	codeSealedRefused  = "sealed_refused"
	codeSealedRequired = "sealed_required"
)

// noKeyDetail is a sealed_refused's detail from a node that holds no KEM key.
const noKeyDetail = "this node opens no sealed payload"

// clearRefusals are the codes a provider may answer a sealed request with in
// the clear (E2E design §5.1): the admission refusals, which carry no
// application data, a STREAM_OPEN's session admission included.
// sealed_refused is read on its own.
var clearRefusals = []string{"expired", "not_yet_valid", "request_id_reused", "request_copy", "reply_not_kept",
	"caller_quota", "share_full", "admission_full", "too_many_sessions", "unavailable"}

// IsClearRefusal reports whether code may answer a sealed request in the clear.
func IsClearRefusal(code string) bool { return slices.Contains(clearRefusals, code) }

var (
	// ErrKEMAdvertiseDisabled is a ConfidentialRequired offer on a link
	// whose kem_advertise is off: it would name no key and refuse every
	// clear call.
	ErrKEMAdvertiseDisabled = errors.New("stationlink: a required-confidential procedure needs kem_advertise on")
)

// keyed reports whether o's advertisements name this node's KEM key.
func (l *Link) keyed(o Offer) bool {
	return l.kemAdvertise && l.keyring != nil && o.Confidential != ConfidentialOff
}

// kemKey is the key o's advertisement names now, nil for none. Each signing
// reads the keyring, so a renewal names a rotated key.
func (l *Link) kemKey(o Offer) []byte {
	if !l.keyed(o) {
		return nil
	}
	return l.keyring.Current().PublicKey().Carried()
}

// clearAllowed reports whether a procedure takes a clear request now, as
// macula's clear_allowed/2 decides it: never under ConfidentialRequired, and
// once keyed, only while its last keyless advertisement could still be
// served: the longest advertisement lifetime and the clock tolerance from the
// moment it was first keyed.
func (l *Link) clearAllowed(o Offer, now time.Time) bool {
	switch {
	case o.Confidential == ConfidentialRequired:
		return false
	case !l.keyed(o):
		return true
	}
	return !now.After(o.KeyedSince.Add(maxAdvertisementTTL + record.ClockToleranceMs*time.Millisecond))
}

// callSeal is what a sealed request agreed: the reply key, or a stream's two
// keys, and what the answers are bound to.
type callSeal struct {
	keyID   [seal.KeyIDSize]byte
	kRep    [32]byte
	kC2P    [32]byte
	kP2C    [32]byte
	request seal.Request
}

// openRequest opens a sealed request with this node's keyring: its plaintext
// payload and the keys it agreed, or the detail of the sealed_refused it is
// answered with, naming the key this node holds now, or that it holds none.
func (l *Link) openRequest(request frame.VerifiedRequest) (cbor.Value, *callSeal, string) {
	if l.keyring == nil {
		return cbor.Value{}, nil, noKeyDetail
	}
	current := l.keyring.CurrentID()
	refused := hex.EncodeToString(current[:])
	key, held := l.keyring.Find(request.Sealed.KeyID)
	if !held {
		return cbor.Value{}, nil, refused
	}
	ss, err := seal.RecipientSecret(key, request.Sealed.KemCt)
	if err != nil {
		return cbor.Value{}, nil, refused
	}
	parties := seal.Parties{RequestID: request.RequestID, Caller: request.Caller, Target: request.Target}
	kReq, kRep := seal.CallKeys(ss, request.FrameType, parties)
	s := &callSeal{keyID: request.Sealed.KeyID, kRep: kRep, request: sealRequestOf(request)}
	if request.FrameType == seal.FrameStreamOpen {
		s.kC2P, s.kP2C = seal.StreamKeys(ss, parties)
	}
	plain, err := seal.Open(kReq, [seal.NonceSize]byte{}, seal.RequestAAD(s.request), request.Sealed.Ct)
	if err != nil {
		return cbor.Value{}, nil, refused
	}
	payload, err := cbor.Decode(plain)
	if err != nil {
		return cbor.Value{}, nil, refused
	}
	return payload, s, ""
}

// sealRequestOf is a verified request's fields as its seal binds them.
func sealRequestOf(request frame.VerifiedRequest) seal.Request {
	return seal.Request{FrameType: request.FrameType, Realm: request.Realm, Procedure: request.Procedure, Caller: request.Caller,
		Target: request.Target, RequestID: request.RequestID, Deadline: request.Deadline}
}

// sealedAnswer seals a RESULT's payload, or an ERROR's code and detail, under
// the request's reply key with a fresh nonce, bound to the request and to this
// node as the one that responded.
func (s *callSeal) sealedAnswer(frameType string, plain []byte, requestHash [48]byte, respondedBy [32]byte) frame.Sealed {
	nonce := seal.RandomNonce()
	ct := seal.Seal(s.kRep, nonce, seal.ReplyAAD(s.request, frameType, requestHash, respondedBy), plain)
	return frame.Sealed{KeyID: s.keyID, Nonce: nonce[:], Ct: ct}
}
