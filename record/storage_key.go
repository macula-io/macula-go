package record

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
)

// storageKeyLabel opens every storage key a record's fields derive.
const storageKeyLabel = "MACULA-PQ-STORAGE-KEY-V1"

// StorageKey is a record's 32-byte DHT storage key, as macula_record's
// storage_key/1 derives it. A node record is stored under its node_id, and
// every other record under SHA-256 over MACULA-PQ-STORAGE-KEY-V1, a zero byte,
// its type and the fields of its slot, with a 32-byte id as it is and any other
// field length-prefixed. A tombstone takes the key of the record it withdraws.
// A record stored under its signer must be signed or verified (ErrUnsigned). A
// payload without the fields its type's key derives from, a type with no key,
// and a tombstone naming a type outside 1 to 255, which no verifier accepts,
// are ErrMalformed.
func StorageKey(r Record) ([32]byte, error) {
	if r.Type != TypeTombstone {
		return slotKey(int64(r.Type), r.Payload, r.Subject, r.Subject != nil, r)
	}
	withdrawnValue, present := r.Payload.Get("withdrawn_type")
	withdrawn, isInt := withdrawnValue.AsInt64()
	if !present || !isInt {
		return [32]byte{}, fmt.Errorf("%w: a tombstone without an integer withdrawn_type", ErrMalformed)
	}
	subjectValue, hasSubject := r.Payload.Get("subject")
	subject, isBytes := subjectValue.AsBytes()
	if hasSubject && !isBytes {
		return [32]byte{}, fmt.Errorf("%w: a tombstone's subject that is not bytes", ErrMalformed)
	}
	return slotKey(withdrawn, r.Payload, subject, hasSubject, r)
}

// ProcedureKey is the storage key of a procedure's advertisements, from the
// realm id and the procedure's name.
func ProcedureKey(realmID [32]byte, procedure string) [32]byte {
	return derived(int64(TypeProcedureAdvertisement), realmID[:], lengthPrefixed([]byte(procedure)))
}

// ContentKey is the storage key every announcement of a content id shares. A
// content id that is not 50 bytes of tag 2 is ErrNotAContentID.
func ContentKey(mcid []byte) ([32]byte, error) {
	if !isContentID(cbor.Bytes(mcid)) {
		return [32]byte{}, fmt.Errorf("%w: %d bytes", ErrNotAContentID, len(mcid))
	}
	return derived(int64(TypeContentAnnouncement), lengthPrefixed(mcid)), nil
}

// StationEndpointKey is the storage key of a station's endpoint record, from
// the station's node_id.
func StationEndpointKey(nodeID [32]byte) [32]byte {
	return derived(int64(TypeStationEndpoint), nodeID[:])
}

// OrgDirectoryKey is the storage key of an org directory record, from the realm
// id and the org's name.
func OrgDirectoryKey(realmID [32]byte, orgName string) [32]byte {
	return derived(int64(TypeOrgDirectory), realmID[:], lengthPrefixed([]byte(orgName)))
}

// ProcedureDelegationKey is the storage key of a procedure delegation, from the
// org key id and the advertiser's node_id.
func ProcedureDelegationKey(orgKeyID, advertiser [32]byte) [32]byte {
	return derived(int64(TypeProcedureDelegation), orgKeyID[:], advertiser[:])
}

// slotKey is the storage key of a record of type t, as macula_record's slot/4
// derives it from the payload, the subject and the signer's key id.
func slotKey(t int64, payload cbor.Value, subject []byte, hasSubject bool, r Record) ([32]byte, error) {
	fields := slotReader{payload: payload, record: r, recordType: t}
	var key [32]byte
	switch {
	case t == int64(TypeNodeRecord):
		copy(key[:], fields.signer())
	case t == int64(TypeRealmDirectory), t == int64(TypeRealmStations):
		key = derived(t, fields.id("realm_id"))
	case t == int64(TypeRealmMemberEndorsement):
		key = derived(t, fields.id("realm_id"), fields.id("member_node"))
	case t == int64(TypeProcedureAdvertisement):
		key = derived(t, fields.id("realm_id"), lengthPrefixed(fields.text("procedure")))
	case t == int64(TypeFoundationSeedList), t == int64(TypeFoundationRealmTrustList):
		key = derived(t, fields.signer())
	case t == int64(TypeFoundationParameter):
		key = derived(t, fields.signer(), lengthPrefixed(fields.text("param_name")))
	case t == int64(TypeFoundationT3Attestation):
		key = derived(t, fields.id("station_id"))
	case t == int64(TypeContentAnnouncement):
		key = derived(t, lengthPrefixed(fields.contentID("mcid")))
	case t == int64(TypeStationEndpoint):
		key = derived(t, fields.signer())
	case t == int64(TypeOrgDirectory):
		key = derived(t, fields.id("realm_id"), lengthPrefixed(fields.text("org_name")))
	case t == int64(TypeProcedureDelegation):
		key = derived(t, fields.signer(), fields.id("advertiser"))
	case t >= int64(DomainTypeMin) && t <= 0xFF && hasSubject:
		key = derived(t, fields.signer(), lengthPrefixed(subject))
	case t >= int64(DomainTypeMin) && t <= 0xFF:
		key = derived(t, fields.signer())
	default:
		return [32]byte{}, fmt.Errorf("%w: no storage key for type %#02x", ErrMalformed, t)
	}
	if fields.err != nil {
		return [32]byte{}, fields.err
	}
	return key, nil
}

// slotReader reads the fields a storage key derives from, keeping the first
// field it cannot read as its err.
type slotReader struct {
	payload    cbor.Value
	record     Record
	recordType int64
	err        error
}

// id is a 32-byte id from the payload.
func (s *slotReader) id(name string) []byte {
	b, isBytes := payloadField(s.payload, name).AsBytes()
	if !isBytes || len(b) != 32 {
		s.fail(fmt.Errorf("%w: a storage key needs a 32-byte %s", ErrMalformed, name))
	}
	return b
}

// text is a text field from the payload, as its bytes.
func (s *slotReader) text(name string) []byte {
	text, isText := payloadField(s.payload, name).AsText()
	if !isText {
		s.fail(fmt.Errorf("%w: a storage key needs %s as text", ErrMalformed, name))
	}
	return []byte(text)
}

// contentID is a content id from the payload.
func (s *slotReader) contentID(name string) []byte {
	value := payloadField(s.payload, name)
	if !isContentID(value) {
		s.fail(fmt.Errorf("%w: a storage key needs %s as a tag 2 content id", ErrNotAContentID, name))
	}
	b, _ := value.AsBytes()
	return b
}

// signer is the key id of the record's signer, which a record stored under its
// signer has once it is signed or verified.
func (s *slotReader) signer() []byte {
	if s.record.Key == nil {
		s.fail(fmt.Errorf("%w: a record of type %#02x is stored under its signer", ErrUnsigned, s.recordType))
	}
	return s.record.KeyID[:]
}

func (s *slotReader) fail(err error) {
	if s.err == nil {
		s.err = err
	}
}

// derived is SHA-256 over the storage key label, a zero byte, the type's tag
// and the fields, each already in its form: a 32-byte id as it is, any other
// field length-prefixed.
func derived(t int64, fields ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(storageKeyLabel))
	h.Write([]byte{0, byte(t)})
	for _, field := range fields {
		h.Write(field)
	}
	var key [32]byte
	h.Sum(key[:0])
	return key
}

// lengthPrefixed is b after its length as 4 bytes, big-endian.
func lengthPrefixed(b []byte) []byte {
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(b))), b...)
}
