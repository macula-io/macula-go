package record

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"github.com/macula-io/macula-go/profile"
)

// The refusals of a procedure advertisement's provider authorization, named as
// macula_record's verify_authorization/3 names them. A name starting with a
// slash, an org directory and a procedure delegation that are not both byte
// strings, and a record that is not a procedure advertisement are ErrMalformed,
// and an authorization in any other form is ErrAuthorizationFormUnsupported.
var (
	// ErrNoAuthorization is a procedure with an org namespace whose
	// advertisement carries no authorization.
	ErrNoAuthorization = errors.New("record: a procedure with an org namespace carries no authorization")
	// ErrAuthorizationNotAllowed is a procedure without an org namespace whose
	// advertisement carries an authorization.
	ErrAuthorizationNotAllowed = errors.New("record: a procedure without an org namespace carries an authorization")
	// ErrNoRealmKey is an authorization checked without a trusted realm key.
	ErrNoRealmKey = errors.New("record: the authorization needs the trusted realm key")
	// ErrOrgDirectoryInvalid is an org directory that does not verify as one.
	ErrOrgDirectoryInvalid = errors.New("record: the org directory does not verify")
	// ErrOrgDirectoryWrongRealm is an org directory the trusted realm key did
	// not sign, or one for another realm.
	ErrOrgDirectoryWrongRealm = errors.New("record: the org directory is not the trusted realm's for this realm")
	// ErrOrgDirectoryWrongOrg is an org directory for another org.
	ErrOrgDirectoryWrongOrg = errors.New("record: the org directory names another org")
	// ErrDelegationInvalid is a procedure delegation that does not verify as one.
	ErrDelegationInvalid = errors.New("record: the procedure delegation does not verify")
	// ErrDelegationMismatch is a procedure delegation the org key did not sign,
	// or one for another advertiser.
	ErrDelegationMismatch = errors.New("record: the procedure delegation is not the org's for this advertiser")
	// ErrAuthorizationOutlived is an advertisement that expires after its org
	// directory or its procedure delegation.
	ErrAuthorizationOutlived = errors.New("record: the advertisement outlives its authorization")
)

// Trust is what a caller trusts for its realm: the verifier's profile and the
// realm key as carried. macula 11.0.0's realm issues no certificates, so no
// realm CA is trusted for a provider's authorization.
type Trust struct {
	Profile  profile.Profile
	RealmKey []byte
}

// ProcedureOrg is a procedure's org namespace, as macula_record's
// procedure_org/1 reads it: the text before the first "/" of its name. A name
// without a slash, or with "_" before it, has none. A name starting with a
// slash is ErrMalformed.
func ProcedureOrg(procedure string) (org string, hasOrg bool, err error) {
	before, _, hasSlash := strings.Cut(procedure, "/")
	switch {
	case !hasSlash, before == "_":
		return "", false, nil
	case before == "":
		return "", false, fmt.Errorf("%w: a procedure name starting with a slash", ErrMalformed)
	}
	return before, true, nil
}

// VerifyAuthorization is the caller's check of a verified procedure
// advertisement's provider authorization against the realm it trusts, as
// macula_record's verify_authorization/3 does for 11.0.0, with nowMs the
// caller's clock in Unix milliseconds. It takes a Verified, a record Verify
// returned, so the advertiser node it checks is the one the advertisement's
// signature covers; the zero Verified, like any record that is not a procedure
// advertisement, is ErrMalformed. A procedure with an org namespace needs an
// authorization (ErrNoAuthorization), and one without carries none, in any form
// (ErrAuthorizationNotAllowed).
//
// The authorization is an org directory and a procedure delegation, and needs
// Trust.RealmKey (ErrNoRealmKey). The org directory must verify as one at nowMs
// (ErrOrgDirectoryInvalid), carry the realm key and name the advertisement's
// realm (ErrOrgDirectoryWrongRealm) and the procedure's org
// (ErrOrgDirectoryWrongOrg). The procedure delegation must verify as one at
// nowMs (ErrDelegationInvalid), signed by the org key the directory names, for
// the advertiser (ErrDelegationMismatch). The advertisement expires no later
// than either (ErrAuthorizationOutlived). An authorization in any other form, a
// certificate chain among them, is ErrAuthorizationFormUnsupported, and an org
// directory and a procedure delegation that are not both byte strings are
// ErrMalformed.
func VerifyAuthorization(advertisement Verified, trust Trust, nowMs int64) error {
	r := advertisement.held
	if r.Type != TypeProcedureAdvertisement {
		return fmt.Errorf("%w: a record of type %#02x is not a procedure advertisement", ErrMalformed, uint8(r.Type))
	}
	read, err := ReadProcedureAdvertisement(r)
	if err != nil {
		return err
	}
	org, hasOrg, err := ProcedureOrg(read.Procedure)
	if err != nil {
		return err
	}
	switch form := read.Authorization.Form; {
	case !hasOrg && form == NoAuthorization:
		return nil
	case !hasOrg:
		return ErrAuthorizationNotAllowed
	case form == NoAuthorization:
		return ErrNoAuthorization
	case form == DelegationAuthorization:
		return delegationPath(r, read, org, trust, nowMs)
	case form == UnsupportedAuthorization:
		return ErrAuthorizationFormUnsupported
	}
	return fmt.Errorf("%w: an org directory and a procedure delegation that are not both byte strings", ErrMalformed)
}

// delegationPath checks an org directory and a procedure delegation as
// macula_record's delegation_path/7 does.
func delegationPath(advertisement Record, read ProcedureAdvertisement, org string, trust Trust, nowMs int64) error {
	if trust.RealmKey == nil {
		return ErrNoRealmKey
	}
	verifiedDirectory, err := Verify(read.Authorization.OrgDirectory, trust.Profile, nowMs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOrgDirectoryInvalid, err)
	}
	directory := verifiedDirectory.held
	named, err := ReadOrgDirectory(directory)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOrgDirectoryInvalid, err)
	}
	switch {
	case !bytes.Equal(directory.Key, trust.RealmKey) || named.RealmID != read.RealmID:
		return ErrOrgDirectoryWrongRealm
	case named.OrgName != org:
		return ErrOrgDirectoryWrongOrg
	}
	verifiedDelegation, err := Verify(read.Authorization.ProcedureDelegation, trust.Profile, nowMs)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDelegationInvalid, err)
	}
	delegation := verifiedDelegation.held
	granted, err := ReadProcedureDelegation(delegation)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrDelegationInvalid, err)
	}
	if delegation.KeyID != named.OrgKey || granted.Advertiser != read.AdvertiserNode {
		return ErrDelegationMismatch
	}
	if advertisement.ExpiresAt > min(directory.ExpiresAt, delegation.ExpiresAt) {
		return ErrAuthorizationOutlived
	}
	return nil
}

// OrgDirectory is an org directory's payload, as macula_record's
// read_org_directory/1 reads it: a realm's statement that the org OrgName is
// held by the key with key id OrgKey. A field the payload leaves out, or carries
// as another kind, is zero.
type OrgDirectory struct {
	RealmID [32]byte
	OrgName string
	OrgKey  [32]byte
}

// ReadOrgDirectory reads an org directory's payload. A record of another type
// is ErrMalformed.
func ReadOrgDirectory(r Record) (OrgDirectory, error) {
	if r.Type != TypeOrgDirectory {
		return OrgDirectory{}, fmt.Errorf("%w: a record of type %#02x is not an org directory", ErrMalformed, uint8(r.Type))
	}
	orgName, _ := payloadField(r.Payload, "org_name").AsText()
	directory := OrgDirectory{OrgName: orgName}
	readID(directory.RealmID[:], payloadField(r.Payload, "realm_id"))
	readID(directory.OrgKey[:], payloadField(r.Payload, "org_key"))
	return directory, nil
}

// ProcedureDelegation is a procedure delegation's payload, as macula_record's
// read_procedure_delegation/1 reads it: an org's grant, signed by the org key
// OrgKey names, that the node Advertiser may serve procedures under the org. A
// field the payload leaves out, or carries as another kind, is zero.
type ProcedureDelegation struct {
	OrgKey     [32]byte
	Advertiser [32]byte
}

// ReadProcedureDelegation reads a procedure delegation's payload. A record of
// another type is ErrMalformed.
func ReadProcedureDelegation(r Record) (ProcedureDelegation, error) {
	if r.Type != TypeProcedureDelegation {
		return ProcedureDelegation{}, fmt.Errorf("%w: a record of type %#02x is not a procedure delegation", ErrMalformed, uint8(r.Type))
	}
	var delegation ProcedureDelegation
	readID(delegation.OrgKey[:], payloadField(r.Payload, "org_key"))
	readID(delegation.Advertiser[:], payloadField(r.Payload, "advertiser"))
	return delegation, nil
}
