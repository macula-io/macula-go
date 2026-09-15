package record

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
)

// ErrAuthorizationFormUnsupported is a provider authorization in a form macula
// 11.0.0 does not have, a certificate chain among them: its only form is an org
// directory and a procedure delegation.
var ErrAuthorizationFormUnsupported = errors.New("record: an authorization in a form macula 11.0.0 does not have")

// AuthorizationForm is the form of a procedure advertisement's provider
// authorization, as macula_record's read_authorization/1 reads it.
type AuthorizationForm int

const (
	// NoAuthorization is an advertisement that carries none.
	NoAuthorization AuthorizationForm = iota
	// DelegationAuthorization is the wire forms of the realm's org directory
	// and of the org's procedure delegation, the one form macula 11.0.0 has.
	DelegationAuthorization
	// UnsupportedAuthorization is an authorization map of any other fields, a
	// certificate chain among them.
	UnsupportedAuthorization
	// MalformedAuthorization is an org directory and a procedure delegation
	// that are not both byte strings, or an authorization that is not a map.
	MalformedAuthorization
)

// Authorization is a procedure advertisement's provider authorization, which a
// procedure with an org namespace carries inside the payload: the realm's org
// directory and the org's procedure delegation, as the records' wire forms. A
// storing verifier never parses it.
type Authorization struct {
	Form                AuthorizationForm
	OrgDirectory        []byte
	ProcedureDelegation []byte
}

// ProcedureAdvertisementOptions are a procedure advertisement's optional
// fields, as macula_record's procedure_advertisement/5 takes them: its
// authorization, none by default, and TTLMs, 0 for the default and maximum,
// 5 minutes.
type ProcedureAdvertisementOptions struct {
	Authorization Authorization
	TTLMs         uint64
}

// NewProcedureAdvertisement is an unsigned advertisement, by the node
// advertiserNode, which signs it, of procedure in the realm realmID, served
// through servingStation. It builds no authorization but an org directory and a
// procedure delegation, as macula_record builds no other: the unsupported form
// is ErrAuthorizationFormUnsupported, and the malformed form ErrMalformed.
func NewProcedureAdvertisement(advertiserNode, realmID [32]byte, procedure string, servingStation [32]byte, opts ProcedureAdvertisementOptions) (Record, error) {
	entries := []cbor.MapEntry{
		bytesEntry("realm_id", bytes.Clone(realmID[:])),
		textEntry("procedure", procedure),
		bytesEntry("advertiser_node", bytes.Clone(advertiserNode[:])),
		bytesEntry("serving_station", bytes.Clone(servingStation[:])),
	}
	switch authorization := opts.Authorization; authorization.Form {
	case NoAuthorization:
	case DelegationAuthorization:
		entries = append(entries, valueEntry("authorization", cbor.Map([]cbor.MapEntry{
			bytesEntry("org_directory", bytes.Clone(authorization.OrgDirectory)),
			bytesEntry("procedure_delegation", bytes.Clone(authorization.ProcedureDelegation)),
		})))
	case UnsupportedAuthorization:
		return Record{}, ErrAuthorizationFormUnsupported
	default:
		return Record{}, fmt.Errorf("%w: an authorization in no form", ErrMalformed)
	}
	return unsigned(TypeProcedureAdvertisement, cbor.Map(entries), opts.TTLMs)
}

// ProcedureAdvertisement is a procedure advertisement's payload, as
// macula_record's read_procedure_advertisement/1 reads it. A field the payload
// leaves out, or carries as another kind, is zero.
type ProcedureAdvertisement struct {
	RealmID        [32]byte
	Procedure      string
	AdvertiserNode [32]byte
	ServingStation [32]byte
	Authorization  Authorization
}

// ReadProcedureAdvertisement reads a procedure advertisement's payload. A record
// of another type is ErrMalformed.
func ReadProcedureAdvertisement(r Record) (ProcedureAdvertisement, error) {
	if r.Type != TypeProcedureAdvertisement {
		return ProcedureAdvertisement{}, fmt.Errorf("%w: a record of type %#02x is not a procedure advertisement", ErrMalformed, uint8(r.Type))
	}
	procedure, _ := payloadField(r.Payload, "procedure").AsText()
	advertisement := ProcedureAdvertisement{Procedure: procedure, Authorization: readAuthorization(r.Payload)}
	readID(advertisement.RealmID[:], payloadField(r.Payload, "realm_id"))
	readID(advertisement.AdvertiserNode[:], payloadField(r.Payload, "advertiser_node"))
	readID(advertisement.ServingStation[:], payloadField(r.Payload, "serving_station"))
	return advertisement, nil
}

// readAuthorization reads an advertisement's authorization as macula_record's
// read_authorization/1 does: none when it is absent; the delegation form for a
// map of exactly org_directory and procedure_delegation, both byte strings;
// malformed for those two fields when they are not both byte strings, or for a
// value that is not a map; and the unsupported form for a map of any other
// fields, a certificate chain among them.
func readAuthorization(payload cbor.Value) Authorization {
	value, present := payload.Get("authorization")
	if !present {
		return Authorization{}
	}
	entries, isMap := value.AsMap()
	directoryValue, hasDirectory := value.Get("org_directory")
	delegationValue, hasDelegation := value.Get("procedure_delegation")
	switch {
	case !isMap:
		return Authorization{Form: MalformedAuthorization}
	case len(entries) != 2 || !hasDirectory || !hasDelegation:
		return Authorization{Form: UnsupportedAuthorization}
	}
	directory, isDirectory := directoryValue.AsBytes()
	delegation, isDelegation := delegationValue.AsBytes()
	if !isDirectory || !isDelegation {
		return Authorization{Form: MalformedAuthorization}
	}
	return Authorization{Form: DelegationAuthorization, OrgDirectory: bytes.Clone(directory),
		ProcedureDelegation: bytes.Clone(delegation)}
}
