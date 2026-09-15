// Package record signs and verifies macula 11.0.0's records, as macula_record
// does (DESIGN_PQ_SIGNED_FRAMES_AND_RECORDS.md). A record is the signed object
// {key, tbs, signature} under MACULA-PQ-RECORD-V1. Its tbs holds type, alg,
// version, created_at, expires_at and payload, and subject only on a domain type
// (tags 0x20 to 0xFF). Sign takes the signer's key and refuses a key whose
// purpose does not fit the type; Verify reads a record's wire form in the
// design's order and keeps its tbs bytes, so Encode sends them unchanged.
//
// A record is named by the key id of its key: the node_id for node records,
// procedure advertisements, content announcements and station endpoints, and
// the MACULA-KEY-ID-V1 key id for realm, org and foundation records and for
// every domain type. A tombstone is named as the type it withdraws.
package record

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The label a record's signature covers, and the bounds a record keeps.
const (
	label = "MACULA-PQ-RECORD-V1"

	// MaxRecordBytes is the longest wire form a record may have, 256 KiB.
	MaxRecordBytes = 256 * 1024
	// ClockToleranceMs is how far a verifier's clock may be from a record's
	// created_at and expires_at, 5 minutes.
	ClockToleranceMs = 5 * minuteMs
	// MaxEndorsementWindowMs is the longest a realm member endorsement admits
	// its member, 30 days.
	MaxEndorsementWindowMs = 30 * dayMs

	maxProtocolInt    = 1 << 53
	maxPayloadNesting = 63

	minuteMs = 60 * 1000
	hourMs   = 60 * minuteMs
	dayMs    = 24 * hourMs
)

// Type is a record's type tag.
type Type uint8

// The record types macula 11.0.0 defines. Tags from DomainTypeMin to 0xFF are
// domain types, whose owners set their payload rules.
const (
	TypeNodeRecord               Type = 0x01
	TypeRealmDirectory           Type = 0x03
	TypeRealmStations            Type = 0x04
	TypeRealmMemberEndorsement   Type = 0x05
	TypeProcedureAdvertisement   Type = 0x06
	TypeTombstone                Type = 0x0C
	TypeFoundationSeedList       Type = 0x0D
	TypeFoundationParameter      Type = 0x0E
	TypeFoundationRealmTrustList Type = 0x0F
	TypeFoundationT3Attestation  Type = 0x10
	TypeContentAnnouncement      Type = 0x11
	TypeStationEndpoint          Type = 0x12
	TypeOrgDirectory             Type = 0x15
	TypeProcedureDelegation      Type = 0x16
	DomainTypeMin                Type = 0x20
)

// The longest a record of a type lives, created_at to expires_at (D28): a node
// record and a content announcement 48 hours; a procedure advertisement and a
// station endpoint 5 minutes; realm stations, an org directory and a procedure
// delegation 6 hours; a realm member endorsement 30 days; a domain record 7
// days; and any other type 30 days. A tombstone lives at most its withdrawn
// type's maximum plus twice the clock tolerance. A builder given no ttl takes
// 48 hours, or its type's maximum when that is shorter.
const (
	nodeRecordMaxLifetimeMs             = 48 * hourMs
	contentAnnouncementMaxLifetimeMs    = 48 * hourMs
	procedureAdvertisementMaxLifetimeMs = 5 * minuteMs
	stationEndpointTTLMs                = 5 * minuteMs
	realmAndOrgMaxLifetimeMs            = 6 * hourMs
	domainRecordMaxLifetimeMs           = 7 * dayMs
	defaultMaxLifetimeMs                = 30 * dayMs
	defaultTTLMs                        = 48 * hourMs
)

// The refusals of a record, named as macula_record names them. A signature that
// does not verify is identity.ErrObjectSignatureInvalid, a signed object whose
// alg names another profile is identity.ErrObjectAlgMismatch, and a binary
// without ML-DSA refuses with identity.ErrPostQuantumUnavailable.
var (
	// ErrRecordTooLarge is a record whose wire form is over 256 KiB.
	ErrRecordTooLarge = errors.New("record: over 256 KiB")
	// ErrMalformed is a record without exactly the shape, fields and payload of
	// its type.
	ErrMalformed = errors.New("record: malformed")
	// ErrNotYetValid is a record created more than 5 minutes ahead of the
	// verifier's clock.
	ErrNotYetValid = errors.New("record: not yet valid")
	// ErrExpired is a record that expired more than 5 minutes before the
	// verifier's clock.
	ErrExpired = errors.New("record: expired")
	// ErrKeyIDMismatch is a record whose payload names a signer other than the
	// key id of its key.
	ErrKeyIDMismatch = errors.New("record: the payload names a signer other than its key")
	// ErrLifetimeTooLong is a record that lives longer than its type's maximum.
	ErrLifetimeTooLong = errors.New("record: a lifetime over its type's maximum")
	// ErrLifetimeReversed is a record that expires no later than it is created.
	ErrLifetimeReversed = errors.New("record: expires no later than it is created")
	// ErrKeyPurposeMismatch is a key whose purpose does not fit the type it would
	// sign.
	ErrKeyPurposeMismatch = errors.New("record: a key whose purpose does not fit the type")
	// ErrUnsigned is a record with no key, tbs or signature to encode.
	ErrUnsigned = errors.New("record: not signed")
	// ErrNotADomainType is a domain envelope for a built-in type.
	ErrNotADomainType = errors.New("record: not a domain type")
	// ErrInvalidSubject is a domain record's subject that is empty.
	ErrInvalidSubject = errors.New("record: an empty subject")
)

// Record is a record: unsigned as a builder returns it, or signed or verified,
// when Key, KeyID, Alg, TBS and Signature hold what signing or verifying gave.
// Payload is a map. Subject names a domain record's subject, nil for none and on
// every other type.
type Record struct {
	Type      Type
	Version   [16]byte
	CreatedAt uint64
	ExpiresAt uint64
	Payload   cbor.Value
	Subject   []byte

	Key       []byte
	KeyID     [32]byte
	Alg       string
	TBS       []byte
	Signature []byte
}

// unsigned is a record of type t, created now with a UUIDv7 version, living
// ttlMs, or its type's default when ttlMs is 0.
func unsigned(t Type, payload cbor.Value, ttlMs uint64) (Record, error) {
	version, err := uuid.NewV7()
	if err != nil {
		return Record{}, fmt.Errorf("record: version: %w", err)
	}
	if ttlMs == 0 {
		ttlMs = uint64(defaultTTL(t))
	}
	now := uint64(time.Now().UnixMilli())
	return Record{Type: t, Version: version, CreatedAt: now, ExpiresAt: now + ttlMs, Payload: payload}, nil
}

// Envelope is an unsigned record of a domain type, from DomainTypeMin to 0xFF,
// with subject, nil for none, living ttlMs, or 48 hours when ttlMs is 0. A
// built-in type is ErrNotADomainType, and an empty subject is
// ErrInvalidSubject, since it would name a slot apart from no subject.
func Envelope(t Type, payload cbor.Value, subject []byte, ttlMs uint64) (Record, error) {
	if t < DomainTypeMin {
		return Record{}, fmt.Errorf("%w: %#02x", ErrNotADomainType, uint8(t))
	}
	if subject != nil && len(subject) == 0 {
		return Record{}, ErrInvalidSubject
	}
	r, err := unsigned(t, payload, ttlMs)
	r.Subject = bytes.Clone(subject)
	return r, err
}

// Sign signs r with key, as macula_record's sign/2 does, and returns it with its
// key, key id, alg, tbs and signature. It refuses an empty subject first
// (ErrInvalidSubject), since every reader refuses one, and then checks, in
// macula's order, and refuses a key whose purpose does not fit r's type
// (ErrKeyPurposeMismatch); a lifetime that runs backwards (ErrLifetimeReversed)
// or past its type's maximum (ErrLifetimeTooLong); a payload that names a
// signer other than key (ErrKeyIDMismatch); and a record over 256 KiB
// (ErrRecordTooLarge).
func Sign(r Record, key *identity.NodeKey) (Record, error) {
	carried := key.PublicKey()
	if carried == nil {
		return Record{}, identity.ErrEmptyNodeKey
	}
	if r.Subject != nil && len(r.Subject) == 0 {
		return Record{}, ErrInvalidSubject
	}
	p := key.Profile()
	if !slices.Contains(signerPurposes(int64(r.Type), r.Payload), key.Purpose()) {
		return Record{}, fmt.Errorf("%w: a %s key for type %#02x", ErrKeyPurposeMismatch, key.Purpose(), uint8(r.Type))
	}
	if err := lifetime(r); err != nil {
		return Record{}, fmt.Errorf("%w: type %#02x", err, uint8(r.Type))
	}
	keyID := keyIDOf(signerKind(int64(r.Type), r.Payload), carried, p)
	if !namedSigner(r.Type, r.Payload, keyID) {
		return Record{}, fmt.Errorf("%w: type %#02x", ErrKeyIDMismatch, uint8(r.Type))
	}
	fields := tbsFields(r)
	if size := len(cbor.Encode(cbor.Map(fields))) + len(carried) + identity.SignatureSize(p); size > MaxRecordBytes {
		return Record{}, fmt.Errorf("%w: %d bytes before signing", ErrRecordTooLarge, size)
	}
	object, err := identity.SignObject(label, fields, key)
	if err != nil {
		return Record{}, err
	}
	if size := len(cbor.Encode(object.Value())); size > MaxRecordBytes {
		return Record{}, fmt.Errorf("%w: %d bytes signed", ErrRecordTooLarge, size)
	}
	definition, err := p.Definition()
	if err != nil {
		return Record{}, err
	}
	r.Key, r.KeyID, r.Alg, r.TBS, r.Signature = carried, keyID, definition.SigAlg, object.TBS, object.Signature
	return r, nil
}

// Refresh is r with a new version, created now, with the same lifetime, signed
// again with key.
func Refresh(r Record, key *identity.NodeKey) (Record, error) {
	version, err := uuid.NewV7()
	if err != nil {
		return Record{}, fmt.Errorf("record: version: %w", err)
	}
	now := time.Now().UnixMilli()
	expires := max(now+int64(r.ExpiresAt)-int64(r.CreatedAt), 0)
	fresh := Record{Type: r.Type, Version: version, CreatedAt: uint64(now), ExpiresAt: uint64(expires),
		Payload: r.Payload, Subject: r.Subject}
	return Sign(fresh, key)
}

// Encode is the wire form of a signed or verified record: its {key, tbs,
// signature} map, tbs unchanged. A record with no key, tbs or signature is
// ErrUnsigned.
func Encode(r Record) ([]byte, error) {
	if r.Key == nil || r.TBS == nil || r.Signature == nil {
		return nil, ErrUnsigned
	}
	return cbor.Encode(identity.Object{Key: r.Key, TBS: r.TBS, Signature: r.Signature}.Value()), nil
}

// Verify reads a record's wire form under the verifier's profile p and clock
// nowMs in Unix milliseconds, as macula_record's verify/3 does, in this order:
// a wire form over 256 KiB (ErrRecordTooLarge), before anything is decoded; a
// signed object that carries its key (ErrMalformed); its signature under
// MACULA-PQ-RECORD-V1 and its alg (identity.ErrObjectSignatureInvalid,
// identity.ErrObjectAlgMismatch, or ErrMalformed for a key or tbs of another
// shape); a tbs of exactly type, alg, version, created_at, expires_at and
// payload, with subject only on a domain type (ErrMalformed); created_at no
// more than 5 minutes ahead of nowMs (ErrNotYetValid) and expires_at no more
// than 5 minutes behind it (ErrExpired), both bounds included; a lifetime
// within its type's maximum (ErrLifetimeReversed, ErrLifetimeTooLong); its
// type's payload rules (ErrMalformed); and a payload that names its signer by
// the key's id (ErrKeyIDMismatch). A binary without ML-DSA refuses with
// identity.ErrPostQuantumUnavailable. Refusals are returned, never raised.
func Verify(wire []byte, p profile.Profile, nowMs int64) (Record, error) {
	if len(wire) > MaxRecordBytes {
		return Record{}, ErrRecordTooLarge
	}
	object, err := identity.DecodeObject(wire)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	verified, err := identity.VerifyObject(label, object.Value(), p)
	if err != nil {
		return Record{}, objectRefusal(err)
	}
	r, ok := readTBS(verified.Fields)
	if !ok {
		return Record{}, ErrMalformed
	}
	r.Key, r.TBS, r.Signature = verified.Key, verified.TBS, bytes.Clone(object.Signature)
	if err := clock(r, nowMs); err != nil {
		return Record{}, err
	}
	if err := lifetime(r); err != nil {
		return Record{}, err
	}
	if !payloadOK(r.Type, r.Payload) {
		return Record{}, ErrMalformed
	}
	r.KeyID = keyIDOf(signerKind(int64(r.Type), r.Payload), r.Key, p)
	if !namedSigner(r.Type, r.Payload, r.KeyID) {
		return Record{}, ErrKeyIDMismatch
	}
	return r, nil
}

// objectRefusal is the refusal of a record whose signed object did not verify:
// a malformed object as ErrMalformed, and any other refusal as it is.
func objectRefusal(err error) error {
	if errors.Is(err, identity.ErrObjectMalformed) {
		return fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	return err
}

// PayloadBounded checks a payload before anything is signed, as macula_record's
// payload_bounded/1 does: its encoding is at most 256 KiB (ErrRecordTooLarge),
// and it nests at most 63 levels of maps and lists (ErrMalformed), which a
// record's tbs leaves it under the decoding rule's 64. Go measures the CBOR
// encoding where macula measures the Erlang term.
func PayloadBounded(payload cbor.Value) error {
	if size := len(cbor.Encode(payload)); size > MaxRecordBytes {
		return fmt.Errorf("%w: a payload of %d bytes", ErrRecordTooLarge, size)
	}
	if nesting(payload, 0) > maxPayloadNesting {
		return fmt.Errorf("%w: a payload nested past %d levels", ErrMalformed, maxPayloadNesting)
	}
	return nil
}

// nesting is how deep v nests maps and lists below depth, counted no further
// than one level past the bound.
func nesting(v cbor.Value, depth int) int {
	var children []cbor.Value
	switch v.Kind() {
	case cbor.KindList:
		children, _ = v.AsList()
	case cbor.KindMap:
		entries, _ := v.AsMap()
		for _, e := range entries {
			children = append(children, e.Key, e.Val)
		}
	default:
		return depth
	}
	deepest := depth + 1
	for _, child := range children {
		if deepest > maxPayloadNesting {
			break
		}
		deepest = max(deepest, nesting(child, depth+1))
	}
	return deepest
}

// tbsFields is the fields of r's tbs; signing adds alg.
func tbsFields(r Record) []cbor.MapEntry {
	fields := []cbor.MapEntry{
		uintEntry("type", uint64(r.Type)),
		bytesEntry("version", r.Version[:]),
		uintEntry("created_at", r.CreatedAt),
		uintEntry("expires_at", r.ExpiresAt),
		valueEntry("payload", r.Payload),
	}
	if r.Subject != nil {
		fields = append(fields, bytesEntry("subject", r.Subject))
	}
	return fields
}

// readTBS reads a verified record's tbs, as macula_record's read_tbs does:
// exactly type (1 to 255), alg (text), version (16 bytes), created_at and
// expires_at (below 2^53), payload (a map), and subject (bytes, not empty) only
// on a domain type. Each field must be present, since a missing one reads as
// the zero cbor.Value, the integer 0. The tbs's size counts every key, text or
// not, as map_size/1 counts it.
func readTBS(tbs cbor.Value) (Record, bool) {
	entries, isMap := tbs.AsMap()
	if !isMap {
		return Record{}, false
	}
	fields := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		if name, isText := e.Key.AsText(); isText {
			fields[name] = e.Val
		}
	}
	for _, name := range []string{"type", "alg", "version", "created_at", "expires_at", "payload"} {
		if _, present := fields[name]; !present {
			return Record{}, false
		}
	}
	t, isType := fields["type"].AsInt64()
	alg, isAlg := fields["alg"].AsText()
	version, isVersion := fields["version"].AsBytes()
	created, isCreated := protocolUint(fields["created_at"])
	expires, isExpires := protocolUint(fields["expires_at"])
	_, isPayload := fields["payload"].AsMap()
	if !isType || t < 1 || t > 0xFF || !isAlg || !isVersion || len(version) != 16 || !isCreated || !isExpires || !isPayload {
		return Record{}, false
	}
	r := Record{Type: Type(t), CreatedAt: created, ExpiresAt: expires, Payload: fields["payload"], Alg: alg}
	copy(r.Version[:], version)
	subject, hasSubject := fields["subject"]
	switch len(entries) {
	case 6:
		return r, !hasSubject
	case 7:
		b, isBytes := subject.AsBytes()
		r.Subject = bytes.Clone(b)
		return r, isBytes && len(b) > 0 && r.Type >= DomainTypeMin
	}
	return Record{}, false
}

func protocolUint(v cbor.Value) (uint64, bool) {
	n, isInt := v.AsInt64()
	return uint64(n), isInt && n >= 0 && n < maxProtocolInt
}

// clock refuses a record created more than the clock tolerance ahead of nowMs,
// or expired more than the tolerance before it.
func clock(r Record, nowMs int64) error {
	switch {
	case int64(r.CreatedAt) > nowMs+ClockToleranceMs:
		return ErrNotYetValid
	case int64(r.ExpiresAt)+ClockToleranceMs < nowMs:
		return ErrExpired
	}
	return nil
}

// lifetime refuses a record whose lifetime, created_at to expires_at, does not
// run forward or is longer than its type's maximum.
func lifetime(r Record) error {
	lived := int64(r.ExpiresAt) - int64(r.CreatedAt)
	switch {
	case lived <= 0:
		return ErrLifetimeReversed
	case lived > maxLifetime(int64(r.Type), r.Payload):
		return ErrLifetimeTooLong
	}
	return nil
}

// maxLifetime is the longest a record of type t lives, as macula_record's
// max_lifetime/2 has it. A tombstone's follows the type its payload withdraws,
// plus twice the clock tolerance: the record it withdraws may be created up to
// the tolerance ahead, and the tombstone outlives it by the tolerance. A
// withdrawn_type that is not an integer is read as a type with no rule of its
// own, as Erlang's term order has it, and the payload rules then refuse it.
func maxLifetime(t int64, payload cbor.Value) int64 {
	switch {
	case t == int64(TypeNodeRecord):
		return nodeRecordMaxLifetimeMs
	case t == int64(TypeContentAnnouncement):
		return contentAnnouncementMaxLifetimeMs
	case t == int64(TypeProcedureAdvertisement):
		return procedureAdvertisementMaxLifetimeMs
	case t == int64(TypeStationEndpoint):
		return stationEndpointTTLMs
	case t == int64(TypeRealmStations), t == int64(TypeOrgDirectory), t == int64(TypeProcedureDelegation):
		return realmAndOrgMaxLifetimeMs
	case t == int64(TypeRealmMemberEndorsement):
		return MaxEndorsementWindowMs
	case t == int64(TypeTombstone):
		withdrawnValue, has := payload.Get("withdrawn_type")
		withdrawn, isInt := withdrawnValue.AsInt64()
		switch {
		case !has || (isInt && withdrawn == int64(TypeTombstone)):
			return defaultMaxLifetimeMs
		case !isInt:
			return defaultMaxLifetimeMs + 2*ClockToleranceMs
		}
		return maxLifetime(withdrawn, cbor.Map(nil)) + 2*ClockToleranceMs
	case t >= int64(DomainTypeMin):
		return domainRecordMaxLifetimeMs
	}
	return defaultMaxLifetimeMs
}

// defaultTTL is the lifetime a builder given no ttl takes: 48 hours, or the
// type's maximum when that is shorter.
func defaultTTL(t Type) int64 {
	return min(defaultTTLMs, maxLifetime(int64(t), cbor.Map(nil)))
}

// signerPurposes is the purposes of the keys that may sign a record of type t,
// as macula_record's signer_purposes/2 has them. A tombstone is signed like the
// type it withdraws. Go keys have the identity and connect purposes, so a Go key
// signs only the types an identity key signs; a tombstone whose withdrawn_type
// is not an integer is signed by no Go key.
func signerPurposes(t int64, payload cbor.Value) []identity.Purpose {
	switch {
	case t == int64(TypeTombstone):
		withdrawnValue, has := payload.Get("withdrawn_type")
		withdrawn, isInt := withdrawnValue.AsInt64()
		if !has || !isInt {
			return nil
		}
		return signerPurposes(withdrawn, cbor.Map(nil))
	case t == int64(TypeNodeRecord), t == int64(TypeProcedureAdvertisement), t == int64(TypeContentAnnouncement),
		t == int64(TypeStationEndpoint):
		return []identity.Purpose{identity.PurposeIdentity}
	case t == int64(TypeRealmDirectory), t == int64(TypeRealmStations), t == int64(TypeRealmMemberEndorsement),
		t == int64(TypeOrgDirectory):
		return []identity.Purpose{"realm"}
	case t == int64(TypeProcedureDelegation):
		return []identity.Purpose{"org"}
	case t >= int64(TypeFoundationSeedList) && t <= int64(TypeFoundationT3Attestation):
		return []identity.Purpose{"foundation"}
	case t >= int64(DomainTypeMin):
		return []identity.Purpose{identity.PurposeIdentity, "realm", "org", "foundation"}
	}
	return nil
}

// A record is named by its signer's node_id on the node-signed types and by its
// key id on every other type.
type keyKind int

const (
	nodeKind keyKind = iota
	otherKind
)

// signerKind is how a record of type t names its signer. A tombstone is named as
// the type it withdraws.
func signerKind(t int64, payload cbor.Value) keyKind {
	if t == int64(TypeTombstone) {
		withdrawnValue, _ := payload.Get("withdrawn_type")
		withdrawn, isInt := withdrawnValue.AsInt64()
		if !isInt {
			return otherKind
		}
		t = withdrawn
	}
	switch t {
	case int64(TypeNodeRecord), int64(TypeProcedureAdvertisement), int64(TypeContentAnnouncement), int64(TypeStationEndpoint):
		return nodeKind
	}
	return otherKind
}

func keyIDOf(kind keyKind, carried []byte, p profile.Profile) [32]byte {
	if kind == nodeKind {
		return identity.NodeIDOf(carried, p)
	}
	return identity.KeyIDOf(carried, p)
}

// namedSigner reports whether the payload field that names a type's signer,
// where the type has one, holds keyID.
func namedSigner(t Type, payload cbor.Value, keyID [32]byte) bool {
	var name string
	switch t {
	case TypeNodeRecord:
		name = "node_id"
	case TypeProcedureAdvertisement:
		name = "advertiser_node"
	case TypeContentAnnouncement:
		name = "announcer_node"
	case TypeProcedureDelegation:
		name = "org_key"
	default:
		return true
	}
	value, _ := payload.Get(name)
	named, isBytes := value.AsBytes()
	return isBytes && bytes.Equal(named, keyID[:])
}

func textEntry(name, value string) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Text(value)}
}

func bytesEntry(name string, value []byte) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Bytes(value)}
}

func uintEntry(name string, value uint64) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Uint64(value)}
}

func valueEntry(name string, value cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: value}
}
