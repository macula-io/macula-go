package record

import (
	"bytes"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
)

// AuthorizationForm is the form of a procedure advertisement's provider
// authorization, as macula_record's read_authorization/1 reads it.
type AuthorizationForm int

const (
	// NoAuthorization is an advertisement that carries none.
	NoAuthorization AuthorizationForm = iota
	// DelegationAuthorization is the wire forms of the realm's org directory
	// and of the org's procedure delegation.
	DelegationAuthorization
	// CertificateChainAuthorization is DER certificates, leaf first.
	CertificateChainAuthorization
	// MalformedAuthorization is an authorization in neither form.
	MalformedAuthorization
)

// Authorization is a procedure advertisement's provider authorization, which a
// procedure with an org namespace carries inside the payload. A storing
// verifier never parses it. OrgDirectory and ProcedureDelegation hold the
// delegation form, and CertificateChain the certificate chain form.
type Authorization struct {
	Form                AuthorizationForm
	OrgDirectory        []byte
	ProcedureDelegation []byte
	CertificateChain    [][]byte
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
// through servingStation. An authorization in neither form is ErrMalformed.
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
	case CertificateChainAuthorization:
		chain := make([]cbor.Value, len(authorization.CertificateChain))
		for i, der := range authorization.CertificateChain {
			chain[i] = cbor.Bytes(bytes.Clone(der))
		}
		entries = append(entries, valueEntry("authorization", cbor.Map([]cbor.MapEntry{
			valueEntry("certificate_chain", cbor.List(chain)),
		})))
	default:
		return Record{}, fmt.Errorf("%w: an authorization in neither form", ErrMalformed)
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
// map of exactly org_directory and procedure_delegation; the certificate chain
// form for a map of exactly certificate_chain; and malformed for anything else.
// Go reads each form's values as bytes, so a form holding another kind reads as
// malformed.
func readAuthorization(payload cbor.Value) Authorization {
	value, present := payload.Get("authorization")
	if !present {
		return Authorization{}
	}
	malformed := Authorization{Form: MalformedAuthorization}
	entries, isMap := value.AsMap()
	switch {
	case !isMap:
		return malformed
	case len(entries) == 2:
		directory, isDirectory := payloadField(value, "org_directory").AsBytes()
		delegation, isDelegation := payloadField(value, "procedure_delegation").AsBytes()
		if !isDirectory || !isDelegation {
			return malformed
		}
		return Authorization{Form: DelegationAuthorization, OrgDirectory: bytes.Clone(directory),
			ProcedureDelegation: bytes.Clone(delegation)}
	case len(entries) == 1:
		items, isList := payloadField(value, "certificate_chain").AsList()
		if !isList {
			return malformed
		}
		chain := make([][]byte, 0, len(items))
		for _, item := range items {
			der, isBytes := item.AsBytes()
			if !isBytes {
				return malformed
			}
			chain = append(chain, bytes.Clone(der))
		}
		return Authorization{Form: CertificateChainAuthorization, CertificateChain: chain}
	}
	return malformed
}
