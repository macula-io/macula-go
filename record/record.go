// Package record signs and verifies macula 12's records, as macula_record
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
	"github.com/macula-io/macula-go/frame"
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

// The record types macula 12 defines. Tags from DomainTypeMin to 0xFF are
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
	TypeStationAuthorization     Type = 0x13
	TypeOrgDirectory             Type = 0x15
	TypeProcedureDelegation      Type = 0x16
	TypeAppRecord                Type = 0x17
	DomainTypeMin                Type = 0x20
)

// defaultTTLMs is the lifetime a builder given no ttl takes, 48 hours, or its
// type's row's maximum when that is shorter.
const defaultTTLMs = 48 * hourMs

// The refusals of a record, named as macula_record names them. A signature that
// does not verify is identity.ErrObjectSignatureInvalid, a signed object whose
// alg is not the verifier's profile's is identity.ErrObjectAlgUnsupported, and a
// binary without ML-DSA refuses with identity.ErrPostQuantumUnavailable.
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
	// ErrLifetimeClassUnknown is a record whose lifetime_class names no row of
	// the frozen table (lifetime_class_unknown).
	ErrLifetimeClassUnknown = errors.New("record: lifetime_class_unknown")
	// ErrSubjectMissing is a record of a type with no slot rule of its own
	// that carries no subject to place it by (subject_missing).
	ErrSubjectMissing = errors.New("record: subject_missing")
	// ErrTypeUnknown is a record a reader cannot act on: a type it does not
	// know (type_unknown). A custodian stores it.
	ErrTypeUnknown = errors.New("record: type_unknown")
	// ErrSchemaUnsupported is a record whose schema its reader does not read
	// (schema_unsupported).
	ErrSchemaUnsupported = errors.New("record: schema_unsupported")
	// ErrLifetimeClassMismatch is a record whose lifetime_class is not its
	// type's row (lifetime_class_mismatch).
	ErrLifetimeClassMismatch = errors.New("record: lifetime_class_mismatch")
	// ErrMcidTagUnknown is a record naming a content id whose tag its reader
	// does not know (mcid_tag_unknown).
	ErrMcidTagUnknown = errors.New("record: mcid_tag_unknown")
)

// Schema is the schema version every built-in record type has in wire 1.0;
// readers check it, custodians do not (macula docs/design/WIRE_1_0.md 5.1).
const Schema = 1

// maxSchema bounds a schema version.
const maxSchema = 65535

// lifetimeClassMaxMs is the frozen lifetime table (WIRE_1_0.md section 5.1):
// a record's lifetime_class is a row, and its lifetime is at most that row's
// maximum. Rows are only added, and a row's maximum never grows.
var lifetimeClassMaxMs = []int64{5 * minuteMs, 30 * minuteMs, 6 * hourMs, 48 * hourMs, 7 * dayMs, 30 * dayMs}

// The rows the types this library knows name.
const (
	lifetimeClass5Minutes uint8 = iota
	lifetimeClass30Minutes
	lifetimeClass6Hours
	lifetimeClass48Hours
	lifetimeClass7Days
	lifetimeClass30Days
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
	// Schema and LifetimeClass are the tbs's schema version and lifetime
	// row: a builder sets the type's own, Schema and its row.
	Schema        uint16
	LifetimeClass uint8
	// Ext is the tbs's ext map, cbor.Value{} for none.
	Ext cbor.Value

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
	row, _ := typeLifetimeClass(int64(t), payload)
	return Record{Type: t, Version: version, CreatedAt: now, ExpiresAt: now + ttlMs, Payload: payload,
		Schema: Schema, LifetimeClass: row}, nil
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
// key, key id, alg, tbs and signature. It refuses, in macula's order, a key
// whose purpose does not fit r's type (ErrKeyPurposeMismatch); a lifetime that
// runs backwards (ErrLifetimeReversed) or past its type's maximum
// (ErrLifetimeTooLong); a payload that names a signer other than key
// (ErrKeyIDMismatch); a tbs or payload a verifier would refuse (ErrMalformed),
// read from the tbs decoded under the decoding rule as a verifier decodes it, so
// that an empty subject, a payload nested past the rule's depth and a duplicate
// or byte-string map key at any depth are among them; and a record over 256 KiB
// (ErrRecordTooLarge).
func Sign(r Record, key *identity.NodeKey) (Record, error) {
	carried := key.PublicKey()
	if carried == nil {
		return Record{}, identity.ErrEmptyNodeKey
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
	definition, err := p.Definition()
	if err != nil {
		return Record{}, err
	}
	fields := tbsFields(r)
	withAlg := append(slices.Clone(fields), textEntry("alg", definition.SigAlg))
	tbs, err := cbor.Decode(cbor.Encode(cbor.Map(withAlg)))
	if err != nil {
		return Record{}, fmt.Errorf("%w: a record of type %#02x whose tbs the decoding rule refuses: %w", ErrMalformed, uint8(r.Type), err)
	}
	if read, readable := readEnvelopeTBS(tbs); !readable || readerChecks(read) != nil {
		return Record{}, fmt.Errorf("%w: a record of type %#02x that a verifier would refuse", ErrMalformed, uint8(r.Type))
	}
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
		Payload: r.Payload, Subject: r.Subject, Schema: r.Schema, LifetimeClass: r.LifetimeClass, Ext: r.Ext}
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

// Verify reads a record's wire form as a reader does (macula
// docs/design/WIRE_1_0.md section 5.2), under the verifier's profile p and
// clock nowMs in Unix milliseconds. It runs a custodian's checks first
// (CheckAsCustodian): a wire form over 256 KiB (ErrRecordTooLarge); a signed
// object of key, tbs and signature (ErrMalformed); a tbs under the decoding
// rule holding alg as text (ErrMalformed); alg of p's profile, the allowlist
// (identity.ErrObjectAlgUnsupported), and key in its carried form
// (ErrMalformed); the signature (identity.ErrObjectSignatureInvalid); a tbs of
// exactly the envelope keys, each of its type (ErrMalformed); the clock
// (ErrNotYetValid, ErrExpired, 5 minutes of tolerance); the lifetime
// (ErrLifetimeReversed, ErrLifetimeClassUnknown, ErrLifetimeTooLong against
// the row named, then for a known type its own row, ErrLifetimeClassMismatch);
// and the slot (ErrSubjectMissing). Then a reader's own: a type it knows
// (ErrTypeUnknown) and a schema it reads (ErrSchemaUnsupported); an unknown
// critical extension
// (frame.ErrExtensionUnsupported), unknown non-critical ones counted; the
// type's payload rules (ErrMalformed), a content id tag it knows
// (ErrMcidTagUnknown), and a payload that names its signer by the key's id
// (ErrKeyIDMismatch). A binary without ML-DSA refuses with
// identity.ErrPostQuantumUnavailable. It returns the record as a Verified,
// which shares no memory with wire: the decoder copies every byte string out
// of its input, and the key and tbs are copies too.
func Verify(wire []byte, p profile.Profile, nowMs int64) (Verified, error) {
	r, err := custodianChecks(wire, p, nowMs)
	if err != nil {
		return Verified{}, err
	}
	if err := readerKnows(r); err != nil {
		return Verified{}, err
	}
	if r.Ext.Kind() == cbor.KindMap {
		if err := frame.ActOnExt(r.Ext); err != nil {
			return Verified{}, err
		}
	}
	if err := payloadChecks(r); err != nil {
		return Verified{}, err
	}
	if !namedSigner(r.Type, r.Payload, r.KeyID) {
		return Verified{}, ErrKeyIDMismatch
	}
	return Verified{held: r}, nil
}

// CheckAsCustodian runs the checks a station stores a record by (WIRE_1_0.md
// section 5.2, steps 1 to 9, in Verify's order) under p's alg allowlist: it
// never reads a payload
// beyond its type's slot rule and never checks schema, and stores any type,
// known or not. It returns the record's storage key: its type's own slot, or
// for a type with none, H(type | signer key id | subject).
func CheckAsCustodian(wire []byte, p profile.Profile, nowMs int64) ([32]byte, error) {
	r, err := custodianChecks(wire, p, nowMs)
	if err != nil {
		return [32]byte{}, err
	}
	return custodianSlot(r)
}

// custodianChecks runs section 5.2's steps 1 to 9 and returns the record read,
// with the profile its alg selected.
func custodianChecks(wire []byte, p profile.Profile, nowMs int64) (Record, error) {
	if len(wire) > MaxRecordBytes {
		return Record{}, ErrRecordTooLarge
	}
	object, err := identity.DecodeObject(wire)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	verified, err := identity.VerifyObjectByAlg(label, object.Value(), p)
	if err != nil {
		return Record{}, objectRefusal(err)
	}
	r, ok := readEnvelopeTBS(verified.Fields)
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
	if err := ownRow(r); err != nil {
		return Record{}, err
	}
	r.KeyID = keyIDOf(signerKind(int64(r.Type), r.Payload), r.Key, p)
	if _, err := custodianSlot(r); err != nil {
		return Record{}, err
	}
	return r, nil
}

// custodianSlot is a record's slot as a custodian places it: a type with a
// slot rule of its own by that rule, any other by H(type | signer key id |
// subject), refusing one without a subject (ErrSubjectMissing).
func custodianSlot(r Record) ([32]byte, error) {
	if hasOwnSlot(int64(r.Type)) {
		key, err := StorageKey(r)
		switch {
		case errors.Is(err, ErrSubjectMissing):
			return [32]byte{}, err
		case err != nil:
			return [32]byte{}, fmt.Errorf("%w: %w", ErrMalformed, err)
		}
		return key, nil
	}
	if r.Subject == nil {
		return [32]byte{}, fmt.Errorf("%w: type %#02x", ErrSubjectMissing, uint8(r.Type))
	}
	return derived(int64(r.Type), r.KeyID[:], lengthPrefixed(r.Subject)), nil
}

// readerChecks are section 5.2's reader steps 10 and 12 before the signer,
// leaving out step 11, ext, which a builder never acts on.
func readerChecks(r Record) error {
	if err := readerKnows(r); err != nil {
		return err
	}
	return payloadChecks(r)
}

// readerKnows is section 5.2's step 10: a type this library knows and a
// schema it reads.
func readerKnows(r Record) error {
	if _, known := typeLifetimeClass(int64(r.Type), r.Payload); !known {
		return fmt.Errorf("%w: %#02x", ErrTypeUnknown, uint8(r.Type))
	}
	if r.Schema != Schema {
		return fmt.Errorf("%w: schema %d of type %#02x", ErrSchemaUnsupported, r.Schema, uint8(r.Type))
	}
	return nil
}

// ownRow is the end of section 5.2's step 8: a known type (section 5.1) names
// its own row, else ErrLifetimeClassMismatch. A custodian bounds an unknown
// type by the row it names.
func ownRow(r Record) error {
	row, known := typeLifetimeClass(int64(r.Type), r.Payload)
	if known && r.LifetimeClass != row {
		return fmt.Errorf("%w: class %d, type %#02x has %d", ErrLifetimeClassMismatch, r.LifetimeClass, uint8(r.Type), row)
	}
	return nil
}

// payloadChecks is section 5.2's step 12 before the signer: the type's payload
// rules, with no subject on a built-in type that has none (ErrMalformed), and a
// content id tag this library knows (ErrMcidTagUnknown).
func payloadChecks(r Record) error {
	if (r.Subject != nil && r.Type < DomainTypeMin) || !payloadOK(r.Type, r.Payload) {
		return ErrMalformed
	}
	return contentIDTagKnown(r.Type, r.Payload)
}

// Verified is a record Verify returned. Only Verify makes one, and it holds
// memory no caller shares, so nothing a caller does after Verify returns changes
// the record it holds. The zero Verified holds no record.
type Verified struct {
	held Record
}

// Record is a copy of the verified record, sharing no memory with it.
func (v Verified) Record() Record {
	return v.held.clone()
}

// clone is r with its byte slices and its payload copied.
func (r Record) clone() Record {
	r.Key, r.TBS = bytes.Clone(r.Key), bytes.Clone(r.TBS)
	r.Signature, r.Subject = bytes.Clone(r.Signature), bytes.Clone(r.Subject)
	r.Payload, r.Ext = cloneValue(r.Payload), cloneValue(r.Ext)
	return r
}

// cloneValue is v with every byte string, list and map copied. Text, integers
// and floats carry no memory to share.
func cloneValue(v cbor.Value) cbor.Value {
	switch v.Kind() {
	case cbor.KindBytes:
		b, _ := v.AsBytes()
		return cbor.Bytes(bytes.Clone(b))
	case cbor.KindList:
		items, _ := v.AsList()
		copied := make([]cbor.Value, len(items))
		for i, item := range items {
			copied[i] = cloneValue(item)
		}
		return cbor.List(copied)
	case cbor.KindMap:
		entries, _ := v.AsMap()
		copied := make([]cbor.MapEntry, len(entries))
		for i, e := range entries {
			copied[i] = cbor.MapEntry{Key: cloneValue(e.Key), Val: cloneValue(e.Val)}
		}
		return cbor.Map(copied)
	}
	return v
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
	fields = append(fields, uintEntry("schema", uint64(r.Schema)), uintEntry("lifetime_class", uint64(r.LifetimeClass)))
	if r.Subject != nil {
		fields = append(fields, bytesEntry("subject", r.Subject))
	}
	if r.Ext.Kind() == cbor.KindMap {
		fields = append(fields, valueEntry("ext", r.Ext))
	}
	return fields
}

// readEnvelopeTBS reads a verified record's tbs as section 5.2's step 6 does:
// exactly type (1 to 255), alg (text), version (16 bytes), created_at and
// expires_at (below 2^53), schema (1 to 65535), lifetime_class (below 2^53),
// payload (a map, not otherwise read), and, where present, subject (bytes, not
// empty) and ext (a well-formed ext map, not acted on). Each required field
// must be present, since a missing one reads as the zero cbor.Value, the
// integer 0. Keys that are not text count towards the size, so they refuse
// it.
func readEnvelopeTBS(tbs cbor.Value) (Record, bool) {
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
	required := []string{"type", "alg", "version", "created_at", "expires_at", "schema", "lifetime_class", "payload"}
	for _, name := range required {
		if _, present := fields[name]; !present {
			return Record{}, false
		}
	}
	size := len(required)
	t, isType := fields["type"].AsInt64()
	alg, isAlg := fields["alg"].AsText()
	version, isVersion := fields["version"].AsBytes()
	created, isCreated := protocolUint(fields["created_at"])
	expires, isExpires := protocolUint(fields["expires_at"])
	schema, isSchema := fields["schema"].AsInt64()
	class, isClass := protocolUint(fields["lifetime_class"])
	_, isPayload := fields["payload"].AsMap()
	if !isType || t < 1 || t > 0xFF || !isAlg || !isVersion || len(version) != 16 || !isCreated || !isExpires ||
		!isSchema || schema < 1 || schema > maxSchema || !isClass || !isPayload {
		return Record{}, false
	}
	r := Record{Type: Type(t), CreatedAt: created, ExpiresAt: expires, Payload: fields["payload"], Alg: alg,
		Schema: uint16(schema), LifetimeClass: uint8(min(class, 0xFF))}
	if class > 0xFF {
		r.LifetimeClass = 0xFF
	}
	copy(r.Version[:], version)
	if subject, has := fields["subject"]; has {
		b, isBytes := subject.AsBytes()
		if !isBytes || len(b) == 0 {
			return Record{}, false
		}
		r.Subject = bytes.Clone(b)
		size++
	}
	if ext, has := fields["ext"]; has {
		if frame.CheckExt(ext) != nil {
			return Record{}, false
		}
		r.Ext = ext
		size++
	}
	return r, len(entries) == size
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
// run forward, whose lifetime_class names no row of the frozen table, or that
// lives longer than its row's maximum (section 5.1). A tombstone may live twice
// the clock tolerance past its row: it outlives a record that may have been
// created up to the tolerance ahead, by the tolerance.
func lifetime(r Record) error {
	lived := int64(r.ExpiresAt) - int64(r.CreatedAt)
	switch {
	case lived <= 0:
		return ErrLifetimeReversed
	case int(r.LifetimeClass) >= len(lifetimeClassMaxMs):
		return fmt.Errorf("%w: %d", ErrLifetimeClassUnknown, r.LifetimeClass)
	case lived > lifetimeClassMaxMs[r.LifetimeClass]+tombstoneMarginMs(r.Type):
		return ErrLifetimeTooLong
	}
	return nil
}

// tombstoneMarginMs is how far past its row a record of type t may live.
func tombstoneMarginMs(t Type) int64 {
	if t == TypeTombstone {
		return 2 * ClockToleranceMs
	}
	return 0
}

// typeLifetimeClass is the row a record of type t names (section 5.1), and
// whether this library knows the type: node record and content announcement
// 48 hours; procedure advertisement and station endpoint 5 minutes; realm
// stations and org directory 6 hours; procedure delegation, app record and
// station authorization 30 minutes; realm member endorsement 30 days; a domain type 7 days; the other
// built-in types it knows 30 days; and a tombstone the row of the type it
// withdraws, unknown when that type is.
func typeLifetimeClass(t int64, payload cbor.Value) (uint8, bool) {
	switch {
	case t == int64(TypeNodeRecord), t == int64(TypeContentAnnouncement):
		return lifetimeClass48Hours, true
	case t == int64(TypeProcedureAdvertisement), t == int64(TypeStationEndpoint):
		return lifetimeClass5Minutes, true
	case t == int64(TypeRealmStations), t == int64(TypeOrgDirectory):
		return lifetimeClass6Hours, true
	case t == int64(TypeProcedureDelegation), t == int64(TypeAppRecord), t == int64(TypeStationAuthorization):
		return lifetimeClass30Minutes, true
	case t == int64(TypeRealmMemberEndorsement), t == int64(TypeRealmDirectory),
		t >= int64(TypeFoundationSeedList) && t <= int64(TypeFoundationT3Attestation):
		return lifetimeClass30Days, true
	case t == int64(TypeTombstone):
		withdrawnValue, has := payload.Get("withdrawn_type")
		withdrawn, isInt := withdrawnValue.AsInt64()
		if !has || !isInt || withdrawn == int64(TypeTombstone) {
			return lifetimeClass30Days, true
		}
		// A tombstone of a tag this library does not know (a post-1.0 tag) is
		// of an unknown type too: a custodian bounds it by the row it names
		// and a reader refuses it.
		return typeLifetimeClass(withdrawn, cbor.Map(nil))
	case t >= int64(DomainTypeMin) && t <= 0xFF:
		return lifetimeClass7Days, true
	}
	return lifetimeClass30Days, false
}

// hasOwnSlot reports whether a custodian places a record of type t by a slot
// rule of its type's own (StorageKey): every type this library knows.
func hasOwnSlot(t int64) bool {
	_, known := typeLifetimeClass(t, cbor.Map(nil))
	return known
}

// defaultTTL is the lifetime a builder given no ttl takes: 48 hours, or the
// type's row's maximum when that is shorter.
func defaultTTL(t Type) int64 {
	row, _ := typeLifetimeClass(int64(t), cbor.Map(nil))
	return min(defaultTTLMs, lifetimeClassMaxMs[row])
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
		t == int64(TypeOrgDirectory), t == int64(TypeStationAuthorization):
		return []identity.Purpose{"realm"}
	case t == int64(TypeProcedureDelegation), t == int64(TypeAppRecord):
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
	case TypeProcedureDelegation, TypeAppRecord:
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
