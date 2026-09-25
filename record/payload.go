package record

import (
	"slices"

	"github.com/macula-io/macula-go/cbor"
)

// payloadOK reports whether a record's payload holds what its type's rules
// require, as macula_record's payload_ok/2 does: every field a storage key or a
// signer check reads is present, with its kind, and the payloads the design pins
// hold exactly their keys. A domain type's owner sets its rules, and a type
// macula does not define has none that pass.
func payloadOK(t Type, payload cbor.Value) bool {
	entries, isMap := payload.AsMap()
	if !isMap {
		return false
	}
	field := func(name string) cbor.Value {
		value, _ := payload.Get(name)
		return value
	}
	switch t {
	case TypeNodeRecord:
		return isID(field("node_id"))
	case TypeRealmDirectory, TypeRealmStations:
		return isID(field("realm_id"))
	case TypeRealmMemberEndorsement:
		return isID(field("realm_id")) && isID(field("member_node"))
	case TypeProcedureAdvertisement:
		return advertisementPayloadOK(payload, len(entries))
	case TypeTombstone:
		return tombstonePayloadOK(payload, entries)
	case TypeFoundationSeedList, TypeFoundationRealmTrustList, TypeStationEndpoint:
		return true
	case TypeFoundationParameter:
		return isText(field("param_name"))
	case TypeFoundationT3Attestation:
		return isID(field("station_id"))
	case TypeContentAnnouncement:
		procedure, _ := field("procedure").AsText()
		return isID(field("announcer_node")) && isContentID(field("mcid")) &&
			isID(field("realm_id")) && isID(field("serving_station")) && procedure != ""
	case TypeOrgDirectory:
		return isID(field("realm_id")) && isText(field("org_name")) && isID(field("org_key"))
	case TypeProcedureDelegation:
		return isID(field("org_key")) && isID(field("advertiser"))
	}
	return t >= DomainTypeMin
}

// advertisementPayloadOK reports whether a procedure advertisement's payload is
// exactly realm_id, procedure (text), advertiser_node and serving_station, with
// authorization (a map) when it carries one.
func advertisementPayloadOK(payload cbor.Value, size int) bool {
	realmID, _ := payload.Get("realm_id")
	procedure, _ := payload.Get("procedure")
	advertiser, _ := payload.Get("advertiser_node")
	serving, _ := payload.Get("serving_station")
	if !isID(realmID) || !isText(procedure) || !isID(advertiser) || !isID(serving) {
		return false
	}
	authorization, hasAuthorization := payload.Get("authorization")
	_, isMap := authorization.AsMap()
	return (size == 4 && !hasAuthorization) || (size == 5 && hasAuthorization && isMap)
}

// tombstoneFields are a tombstone's own payload fields; the rest are the slot
// fields of the record it withdraws.
var tombstoneFields = []string{"withdrawn_type", "withdrawn_version", "reason", "detail"}

// tombstoneReasons are the reasons a tombstone may give.
var tombstoneReasons = []string{"shutdown", "moved", "revoked"}

// tombstonePayloadOK reports whether a tombstone's payload names what it
// withdraws, as macula_record's tombstone_payload_ok/1 does: withdrawn_type (an
// integer of a type that can be withdrawn), withdrawn_version (16 bytes), reason
// (shutdown, moved or revoked), detail (text) when present, and exactly the
// slot fields of the withdrawn type.
func tombstonePayloadOK(payload cbor.Value, entries []cbor.MapEntry) bool {
	withdrawnValue, _ := payload.Get("withdrawn_type")
	withdrawn, isInt := withdrawnValue.AsInt64()
	versionValue, _ := payload.Get("withdrawn_version")
	version, isVersion := versionValue.AsBytes()
	reasonValue, _ := payload.Get("reason")
	reason, isReason := reasonValue.AsText()
	if !isInt || !isVersion || len(version) != 16 || !isReason {
		return false
	}
	var slot []cbor.MapEntry
	for _, e := range entries {
		if name, isText := e.Key.AsText(); isText && slices.Contains(tombstoneFields, name) {
			continue
		}
		slot = append(slot, e)
	}
	detail, hasDetail := payload.Get("detail")
	return slices.Contains(tombstoneReasons, reason) && withdrawable(withdrawn) && (!hasDetail || isText(detail)) &&
		slotOK(withdrawn, slot)
}

// withdrawable reports whether a record of type t can be withdrawn, as
// macula_record's withdrawable/1 has it at merge-11.0.0 81b90d7c: a domain
// type from 0x20 to 0xFF, or a built-in type below 0x20, other than a
// tombstone, that some key signs. Any other integer names no record type.
func withdrawable(t int64) bool {
	switch {
	case t >= int64(DomainTypeMin) && t <= 0xFF:
		return true
	case t >= 1 && t < int64(DomainTypeMin):
		return t != int64(TypeTombstone) && len(signerPurposes(t, cbor.Map(nil))) > 0
	}
	return false
}

// slotOK reports whether a tombstone's slot fields are exactly the withdrawn
// type's, each of its kind; for a domain type, none or a subject (bytes, not
// empty, since an empty subject would name a slot apart from no subject).
func slotOK(t int64, slot []cbor.MapEntry) bool {
	if t >= int64(DomainTypeMin) {
		if len(slot) == 0 {
			return true
		}
		name, _ := slot[0].Key.AsText()
		subject, isBytes := slot[0].Val.AsBytes()
		return len(slot) == 1 && name == "subject" && isBytes && len(subject) > 0
	}
	names := slotFieldNames(t)
	if len(slot) != len(names) {
		return false
	}
	for _, e := range slot {
		name, isText := e.Key.AsText()
		if !isText || !slices.Contains(names, name) || !slotValueOK(name, e.Val) {
			return false
		}
	}
	return true
}

// slotFieldNames is the payload fields a type's storage key derives from,
// besides its signer's key id, as macula_record's slot_field_names/2 has them.
// A domain type's subject is handled where it is read.
func slotFieldNames(t int64) []string {
	switch t {
	case int64(TypeRealmDirectory), int64(TypeRealmStations):
		return []string{"realm_id"}
	case int64(TypeRealmMemberEndorsement):
		return []string{"realm_id", "member_node"}
	case int64(TypeProcedureAdvertisement):
		return []string{"realm_id", "procedure"}
	case int64(TypeFoundationParameter):
		return []string{"param_name"}
	case int64(TypeFoundationT3Attestation):
		return []string{"station_id"}
	case int64(TypeContentAnnouncement):
		return []string{"mcid"}
	case int64(TypeOrgDirectory):
		return []string{"realm_id", "org_name"}
	case int64(TypeProcedureDelegation):
		return []string{"advertiser"}
	}
	return nil
}

// slotValueOK reports whether a slot field holds its kind: a name as text, an
// MCID, or a 32-byte id.
func slotValueOK(name string, v cbor.Value) bool {
	switch name {
	case "procedure", "param_name", "org_name":
		return isText(v)
	case "mcid":
		return isContentID(v)
	}
	return isID(v)
}

// isID reports whether v is a 32-byte id.
func isID(v cbor.Value) bool {
	b, isBytes := v.AsBytes()
	return isBytes && len(b) == 32
}

func isText(v cbor.Value) bool {
	_, isText := v.AsText()
	return isText
}

// isContentID reports whether v is an MCID: 50 bytes, tag 2 for SHA-384, a codec
// byte and the hash (D24).
func isContentID(v cbor.Value) bool {
	b, isBytes := v.AsBytes()
	return isBytes && len(b) == 50 && b[0] == 2
}
