package record

import (
	"github.com/macula-io/macula-go/cbor"
)

// A station authorization (tag 0x13, macula-station#63) is a realm's
// statement, signed by the realm key, that a node serves it as a station at a
// hostname, in some roles, over a window of at most 30 minutes. It is stored
// under its realm id and station node, and may carry the pair that asks for a
// hardware attestation (macula-station#62).

// The bounds macula_record holds a station authorization to.
const (
	maxStationHostnameBytes         = 253
	maxStationRoleBytes             = 64
	maxStationAuthorizationWindowMs = 30 * minuteMs
)

// stationAuthorizationPayloadOK reports whether a station authorization's
// payload holds what macula_record's station_authorization_payload_ok/1
// requires: realm_id and station_node as 32-byte ids; a hostname of 1 to 253
// bytes of text; roles, each 1 to 64 bytes of text; valid_from and valid_until
// as protocol integers, ending at or after they start and at most 30 minutes
// apart; and the attestation pair under its co-presence bound.
func stationAuthorizationPayloadOK(payload cbor.Value) bool {
	field := func(name string) cbor.Value {
		value, _ := payload.Get(name)
		return value
	}
	hostname, hostnameIsText := field("hostname").AsText()
	return isID(field("realm_id")) && isID(field("station_node")) &&
		hostnameIsText && len(hostname) > 0 && len(hostname) <= maxStationHostnameBytes &&
		stationRolesOK(field("roles")) && stationWindowOK(field("valid_from"), field("valid_until")) &&
		attestationPairOK(payload)
}

func stationRolesOK(v cbor.Value) bool {
	roles, isList := v.AsList()
	if !isList {
		return false
	}
	for _, roleValue := range roles {
		role, isText := roleValue.AsText()
		if !isText || len(role) == 0 || len(role) > maxStationRoleBytes {
			return false
		}
	}
	return true
}

func stationWindowOK(fromValue, untilValue cbor.Value) bool {
	from, fromOK := protocolUint(fromValue)
	until, untilOK := protocolUint(untilValue)
	return fromOK && untilOK && until >= from && until-from <= maxStationAuthorizationWindowMs
}

// attestationPairOK is the co-presence bound: neither attestation_required nor
// attestation_key_id; a 32-byte attestation_key_id alone; or
// attestation_required 1 with one. A record that demands an attestation but
// names no key is refused.
func attestationPairOK(payload cbor.Value) bool {
	required, hasRequired := payload.Get("attestation_required")
	keyID, hasKeyID := payload.Get("attestation_key_id")
	flag, isInt := required.AsInt64()
	switch {
	case !hasRequired && !hasKeyID:
		return true
	case !hasRequired:
		return isID(keyID)
	}
	return isInt && flag == 1 && hasKeyID && isID(keyID)
}

// StationAuthorizationKey is the storage key of a station authorization, from
// the realm id and the station's node_id.
func StationAuthorizationKey(realmID, stationNode [32]byte) [32]byte {
	return derived(int64(TypeStationAuthorization), realmID[:], stationNode[:])
}
