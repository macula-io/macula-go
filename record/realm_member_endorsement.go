package record

import (
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// The refusals of a realm member endorsement, named as
// macula_hyparview_endorsement's verify_endorsement/4 names them. A record
// that does not verify keeps Verify's refusal; an endorsement whose window has
// not started yet wraps ErrNotYetValid, as macula names both not_yet_valid; and
// roles that are not a list are ErrMalformed.
var (
	// ErrWrongType is a record that verifies but is not a realm member
	// endorsement.
	ErrWrongType = errors.New("record: not a realm member endorsement")
	// ErrUntrustedSigner is an endorsement the trusted realm key did not sign.
	ErrUntrustedSigner = errors.New("record: the endorsement is not signed by the trusted realm key")
	// ErrWrongRealm is an endorsement for another realm.
	ErrWrongRealm = errors.New("record: the endorsement is for another realm")
	// ErrWrongMember is an endorsement of another member.
	ErrWrongMember = errors.New("record: the endorsement is for another member")
	// ErrEndorsementExpired is an endorsement whose window ended before the
	// time it is checked at, or that carries no window.
	ErrEndorsementExpired = errors.New("record: the endorsement's window has ended")
	// ErrEndorsementWindowTooLong is an endorsement whose window is longer
	// than MaxEndorsementWindowMs.
	ErrEndorsementWindowTooLong = errors.New("record: the endorsement's window is over 30 days")
	// ErrEndorsementWindowReversed is an endorsement whose window ends before
	// it starts.
	ErrEndorsementWindowReversed = errors.New("record: the endorsement's window ends before it starts")
)

// VerifyRealmMemberEndorsement reports whether an endorsement, as its wire
// form, admitted member to realm at nowMs, and returns the roles it endorsed.
// It checks as macula_hyparview_endorsement's verify_endorsement/4 does, in
// its order: the record verifies at nowMs under trust.Profile (Verify's
// refusals, its created_at and expires_at included); it is a realm member
// endorsement (ErrWrongType); its signer is trust.RealmKey (ErrNoRealmKey when
// there is none, ErrUntrustedSigner); it names realm (ErrWrongRealm) and member
// (ErrWrongMember); its window, valid_from to valid_until, does not end before
// it starts (ErrEndorsementWindowReversed), is at most MaxEndorsementWindowMs
// (ErrEndorsementWindowTooLong), and holds nowMs, both ends included (before
// it, ErrNotYetValid; after it, or a window not carried as two integers,
// ErrEndorsementExpired). Roles not carried as a list are ErrMalformed, and a
// role that is not text is left out, as macula reads them.
//
// nowMs is the time the admission is checked for, so a historical check, such
// as whether an observation's signer was a member when it signed, passes that
// time rather than the current one.
func VerifyRealmMemberEndorsement(wire []byte, trust Trust, realm, member [32]byte, nowMs int64) ([]string, error) {
	verified, err := Verify(wire, trust.Profile, nowMs)
	if err != nil {
		return nil, err
	}
	r := verified.held
	switch {
	case r.Type != TypeRealmMemberEndorsement:
		return nil, ErrWrongType
	case trust.RealmKey == nil:
		return nil, ErrNoRealmKey
	case r.KeyID != identity.KeyIDOf(trust.RealmKey, trust.Profile):
		return nil, ErrUntrustedSigner
	case !payloadID(r.Payload, "realm_id", realm):
		return nil, ErrWrongRealm
	case !payloadID(r.Payload, "member_node", member):
		return nil, ErrWrongMember
	}
	if err := endorsementWindow(r.Payload, nowMs); err != nil {
		return nil, err
	}
	return endorsedRoles(r.Payload)
}

// payloadID reports whether the payload's field name holds exactly id.
func payloadID(payload cbor.Value, name string, id [32]byte) bool {
	var held [32]byte
	return readID(held[:], payloadField(payload, name)) && held == id
}

// endorsementWindow checks an endorsement's window at nowMs as macula's
// check_window/4 and active_window/5 do.
func endorsementWindow(payload cbor.Value, nowMs int64) error {
	from, hasFrom := payloadField(payload, "valid_from").AsInt64()
	until, hasUntil := payloadField(payload, "valid_until").AsInt64()
	switch {
	case !hasFrom || !hasUntil:
		return ErrEndorsementExpired
	case until < from:
		return ErrEndorsementWindowReversed
	// until >= from here, so a negative length is int64 overflow: a window
	// longer than any int64, which macula's integers measure and refuse.
	case until-from < 0 || until-from > MaxEndorsementWindowMs:
		return ErrEndorsementWindowTooLong
	case nowMs < from:
		return fmt.Errorf("%w: the endorsement's window starts at %d", ErrNotYetValid, from)
	case nowMs > until:
		return ErrEndorsementExpired
	}
	return nil
}

// endorsedRoles is the text roles of an endorsement's roles list, in order. A
// payload without roles endorses none; roles carried as anything but a list
// are ErrMalformed.
func endorsedRoles(payload cbor.Value) ([]string, error) {
	v, carried := payload.Get("roles")
	if !carried {
		return []string{}, nil
	}
	items, isList := v.AsList()
	if !isList {
		return nil, fmt.Errorf("%w: an endorsement's roles that are not a list", ErrMalformed)
	}
	roles := []string{}
	for _, item := range items {
		if role, isText := item.AsText(); isText {
			roles = append(roles, role)
		}
	}
	return roles, nil
}
