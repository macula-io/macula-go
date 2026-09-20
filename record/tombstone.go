package record

import (
	"bytes"
	"errors"
	"fmt"
	"slices"

	"github.com/macula-io/macula-go/cbor"
)

// Reason is why a tombstone withdraws a record.
type Reason string

// The reasons a tombstone may give.
const (
	ReasonShutdown Reason = "shutdown"
	ReasonMoved    Reason = "moved"
	ReasonRevoked  Reason = "revoked"
)

var (
	// ErrTombstoneOfATombstone is a tombstone built to withdraw a tombstone.
	ErrTombstoneOfATombstone = errors.New("record: a tombstone cannot withdraw a tombstone")
	// ErrUnknownReason is a tombstone's reason other than shutdown, moved or
	// revoked.
	ErrUnknownReason = errors.New("record: a reason other than shutdown, moved or revoked")
)

// TombstoneOptions are a tombstone's optional fields, as macula_record's
// tombstone/3 takes them: Detail, left out when empty, and TTLMs, 0 for the
// clock tolerance, 5 minutes.
type TombstoneOptions struct {
	Detail string
	TTLMs  uint64
}

// NewTombstone is an unsigned tombstone that withdraws the record withdrawn, as
// macula_record's tombstone/3 builds it. It names the record's type, version
// and slot fields, takes the record's slot, and lives until the record has
// expired plus the clock tolerance, or TTLMs past its own creation when that is
// later, so no replica serves the record again after the tombstone lapses. Sign
// it with the key that signed the record. A tombstone of a tombstone is
// ErrTombstoneOfATombstone, a reason macula does not define is
// ErrUnknownReason, and a record without its slot fields is ErrMalformed.
func NewTombstone(withdrawn Record, reason Reason, opts TombstoneOptions) (Record, error) {
	if withdrawn.Type == TypeTombstone {
		return Record{}, ErrTombstoneOfATombstone
	}
	if !slices.Contains(tombstoneReasons, string(reason)) {
		return Record{}, fmt.Errorf("%w: %q", ErrUnknownReason, reason)
	}
	slot, err := slotFields(withdrawn)
	if err != nil {
		return Record{}, err
	}
	entries := append([]cbor.MapEntry{
		uintEntry("withdrawn_type", uint64(withdrawn.Type)),
		bytesEntry("withdrawn_version", bytes.Clone(withdrawn.Version[:])),
		textEntry("reason", string(reason)),
	}, slot...)
	if opts.Detail != "" {
		entries = append(entries, textEntry("detail", opts.Detail))
	}
	ttlMs := opts.TTLMs
	if ttlMs == 0 {
		ttlMs = ClockToleranceMs
	}
	r, err := unsigned(TypeTombstone, cbor.Map(entries), ttlMs)
	if err != nil {
		return Record{}, err
	}
	r.ExpiresAt = max(r.CreatedAt+ttlMs, withdrawn.ExpiresAt+ClockToleranceMs)
	return r, nil
}

// slotFields is the withdrawn record's slot fields, as macula_record's
// slot_fields/3 takes them: the payload fields its type's storage key derives
// from, or a domain record's subject when it has one.
func slotFields(withdrawn Record) ([]cbor.MapEntry, error) {
	if withdrawn.Type >= DomainTypeMin {
		if withdrawn.Subject == nil {
			return nil, nil
		}
		return []cbor.MapEntry{bytesEntry("subject", bytes.Clone(withdrawn.Subject))}, nil
	}
	var slot []cbor.MapEntry
	for _, name := range slotFieldNames(int64(withdrawn.Type)) {
		value, present := withdrawn.Payload.Get(name)
		if !present {
			return nil, fmt.Errorf("%w: the withdrawn record has no %s", ErrMalformed, name)
		}
		slot = append(slot, valueEntry(name, value))
	}
	return slot, nil
}

// Tombstone is a tombstone's payload, as macula_record's read_tombstone/1 reads
// it: what it withdraws, why, and the withdrawn record's slot fields. A field
// the payload leaves out, or carries as another kind, is zero or nil.
type Tombstone struct {
	WithdrawnType    Type
	WithdrawnVersion [16]byte
	Reason           Reason
	Detail           string
	RealmID          [32]byte
	MemberNode       [32]byte
	Procedure        string
	ParamName        string
	StationID        [32]byte
	MCID             []byte
	OrgName          string
	Advertiser       [32]byte
	Subject          []byte
}

// ReadTombstone reads a tombstone's payload. A record of another type, and a
// withdrawn_type that is not an integer from 1 to 255, which no verifier
// accepts, are ErrMalformed.
func ReadTombstone(r Record) (Tombstone, error) {
	if r.Type != TypeTombstone {
		return Tombstone{}, fmt.Errorf("%w: a record of type %#02x is not a tombstone", ErrMalformed, uint8(r.Type))
	}
	withdrawnValue, present := r.Payload.Get("withdrawn_type")
	withdrawn, isInt := withdrawnValue.AsInt64()
	switch {
	case !present:
		return Tombstone{}, fmt.Errorf("%w: a tombstone that names no withdrawn_type", ErrMalformed)
	case !isInt:
		return Tombstone{}, fmt.Errorf("%w: a withdrawn_type that is not an integer from 1 to 255", ErrMalformed)
	case withdrawn < 1 || withdrawn > 0xFF:
		return Tombstone{}, fmt.Errorf("%w: a withdrawn_type of %d, which names no record type", ErrMalformed, withdrawn)
	}
	text := func(name string) string {
		s, _ := payloadField(r.Payload, name).AsText()
		return s
	}
	mcid, _ := payloadField(r.Payload, "mcid").AsBytes()
	subject, _ := payloadField(r.Payload, "subject").AsBytes()
	tombstone := Tombstone{
		WithdrawnType: Type(withdrawn),
		Reason:        Reason(text("reason")),
		Detail:        text("detail"),
		Procedure:     text("procedure"),
		ParamName:     text("param_name"),
		MCID:          bytes.Clone(mcid),
		OrgName:       text("org_name"),
		Subject:       bytes.Clone(subject),
	}
	if version, isBytes := payloadField(r.Payload, "withdrawn_version").AsBytes(); isBytes && len(version) == 16 {
		copy(tombstone.WithdrawnVersion[:], version)
	}
	readID(tombstone.RealmID[:], payloadField(r.Payload, "realm_id"))
	readID(tombstone.MemberNode[:], payloadField(r.Payload, "member_node"))
	readID(tombstone.StationID[:], payloadField(r.Payload, "station_id"))
	readID(tombstone.Advertiser[:], payloadField(r.Payload, "advertiser"))
	return tombstone, nil
}
