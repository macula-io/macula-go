package record

import (
	"bytes"
	"cmp"
	"errors"
	"reflect"
	"slices"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror verify_authorization/3 and the org namespace in macula's
// macula_record_advertisement_tests at merge-11.0.0 2d2c2ecb, among them
// an_authorization_in_another_form_is_unsupported_test, and the org directory
// and procedure delegation cases in macula_record_tests. A provider's
// authorization has one form, an org directory and a procedure delegation; any
// other form is unsupported. VerifyAuthorization takes a Verified, so every
// advertisement here is signed and verified first. A procedure without an org
// namespace is not pinned here while its rule awaits the namespace change
// (procedure_namespace_required). A Go key signs no org directory or delegation,
// so the realm and org keys here are identity keys that sign those records by
// hand, which a verifier accepts since it does not check a key's purpose. The
// certificate chain that no longer authorizes is in certificate_form_test.go.

type authorizationTestKeys struct {
	realm, org, strangerRealm, strangerOrg *identity.NodeKey
}

var generatedAuthorizationKeys = sync.OnceValues(func() (authorizationTestKeys, error) {
	var keys authorizationTestKeys
	for _, key := range []**identity.NodeKey{&keys.realm, &keys.org, &keys.strangerRealm, &keys.strangerOrg} {
		generated, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQPure)
		if err != nil {
			return authorizationTestKeys{}, err
		}
		*key = generated
	}
	return keys, nil
})

func authorizationKeysFor(t *testing.T) authorizationTestKeys {
	t.Helper()
	return must[authorizationTestKeys](t)(generatedAuthorizationKeys())
}

// delegationOverrides break one link of a delegation bundle at a time.
type delegationOverrides struct {
	directorySigner       *identity.NodeKey
	directoryRealmID      *[32]byte
	directoryOrg          string
	delegationSigner      *identity.NodeKey
	delegationAdvertiser  *[32]byte
	delegationTTLMs       int64
	corruptDirectory      bool
	swapDirectoryAndGrant bool
}

// delegationBundleWire is the wire form of keys.node's advertisement of
// procedure carrying the realm-signed org directory and the org-signed
// delegation, as macula's delegation_bundle/2 builds it, and the trust its
// caller holds.
func delegationBundleWire(t *testing.T, procedure string, o delegationOverrides) ([]byte, Trust) {
	t.Helper()
	keys, authorization := keysFor(t), authorizationKeysFor(t)
	now := nowMs()
	realmID := fill(0x11)
	if o.directoryRealmID != nil {
		realmID = *o.directoryRealmID
	}
	orgKeyID := identity.KeyIDOf(authorization.org.PublicKey(), profile.PQPure)
	directoryPayload := cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", realmID[:]),
		textEntry("org_name", cmp.Or(o.directoryOrg, "acme")), bytesEntry("org_key", orgKeyID[:])})
	directory := signedByHand(t, label, recordFields(t, TypeOrgDirectory, directoryPayload, now, 6*testHour),
		cmp.Or(o.directorySigner, authorization.realm))
	if o.corruptDirectory {
		directory = bytes.Clone(directory)
		directory[len(directory)-5000] ^= 1
	}
	delegationSigner := cmp.Or(o.delegationSigner, authorization.org)
	signerKeyID := identity.KeyIDOf(delegationSigner.PublicKey(), profile.PQPure)
	advertiser := keys.node.KeyID()
	if o.delegationAdvertiser != nil {
		advertiser = *o.delegationAdvertiser
	}
	delegationPayload := cbor.Map([]cbor.MapEntry{bytesEntry("org_key", signerKeyID[:]), bytesEntry("advertiser", advertiser[:])})
	delegation := signedByHand(t, label, recordFields(t, TypeProcedureDelegation, delegationPayload, now,
		cmp.Or(o.delegationTTLMs, 6*testHour)), delegationSigner)
	if o.swapDirectoryAndGrant {
		directory, delegation = delegation, directory
	}
	built := must[Record](t)(NewProcedureAdvertisement(keys.node.KeyID(), fill(0x11), procedure, fill(0x77), ProcedureAdvertisementOptions{
		Authorization: Authorization{Form: DelegationAuthorization, OrgDirectory: directory, ProcedureDelegation: delegation},
		TTLMs:         uint64(5 * testMinute),
	}))
	return wireOf(t, must[Record](t)(Sign(built, keys.node))), Trust{Profile: profile.PQPure, RealmKey: authorization.realm.PublicKey()}
}

// delegationBundle is that advertisement as Verify returns it, with the trust.
func delegationBundle(t *testing.T, procedure string, o delegationOverrides) (Verified, Trust) {
	t.Helper()
	wire, trust := delegationBundleWire(t, procedure, o)
	return must[Verified](t)(Verify(wire, profile.PQPure, nowMs())), trust
}

// signedAdvertisement is key's advertisement of procedure, as Verify returns it.
func signedAdvertisement(t *testing.T, key *identity.NodeKey, procedure string, opts ProcedureAdvertisementOptions) Verified {
	t.Helper()
	built := must[Record](t)(NewProcedureAdvertisement(key.KeyID(), fill(0x11), procedure, fill(2), opts))
	return must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(built, key))), key.Profile(), nowMs()))
}

// signedAdvertisementCarrying is key's advertisement of procedure carrying
// authorization as it is, whatever its form, built by hand since the builder
// builds only the delegation form, and returned as Verify returns it.
func signedAdvertisementCarrying(t *testing.T, key *identity.NodeKey, procedure string, authorization cbor.Value) Verified {
	t.Helper()
	built := must[Record](t)(NewProcedureAdvertisement(key.KeyID(), fill(0x11), procedure, fill(2), ProcedureAdvertisementOptions{}))
	entries, _ := built.Payload.AsMap()
	built.Payload = cbor.Map(withEntry(entries, "authorization", authorization))
	return must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(built, key))), key.Profile(), nowMs()))
}

func TestTheOrgNamespaceIsTheTextBeforeTheFirstSlash(t *testing.T) {
	for _, c := range []struct {
		procedure string
		org       string
		hasOrg    bool
		err       error
	}{
		{"acme/get_forecast_v1", "acme", true, nil},
		{"acme/forecasts/get_v1", "acme", true, nil},
		{"_/posts.get_page", "", false, nil},
		{"echo.ping", "", false, nil},
		{"/get_v1", "", false, ErrMalformed},
	} {
		org, hasOrg, err := ProcedureOrg(c.procedure)
		if org != c.org || hasOrg != c.hasOrg || !errors.Is(err, c.err) || (c.err == nil && err != nil) {
			t.Errorf("the org of %q: %q, %v, %v; want %q, %v, %v", c.procedure, org, hasOrg, err, c.org, c.hasOrg, c.err)
		}
	}
}

func TestAValidDelegationAuthorizesTheAdvertisement(t *testing.T) {
	advertisement, trust := delegationBundle(t, "acme/get_forecast_v1", delegationOverrides{})
	if err := VerifyAuthorization(advertisement, trust, nowMs()); err != nil {
		t.Errorf("a valid delegation: %v, want it authorized", err)
	}
}

// Each link of the delegation, broken on its own, refuses the advertisement for
// that link.
func TestADelegationWithABrokenLinkIsRefused(t *testing.T) {
	authorization := authorizationKeysFor(t)
	otherRealm, otherAdvertiser := fill(0x12), fill(9)
	for _, c := range []struct {
		name      string
		overrides delegationOverrides
		laterMs   int64
		want      error
	}{
		{"an org directory from another realm key", delegationOverrides{directorySigner: authorization.strangerRealm}, 0, ErrOrgDirectoryWrongRealm},
		{"an org directory for another realm id", delegationOverrides{directoryRealmID: &otherRealm}, 0, ErrOrgDirectoryWrongRealm},
		{"an org directory for another org", delegationOverrides{directoryOrg: "acmecorp"}, 0, ErrOrgDirectoryWrongOrg},
		{"a delegation from another org key", delegationOverrides{delegationSigner: authorization.strangerOrg}, 0, ErrDelegationMismatch},
		{"a delegation for another advertiser", delegationOverrides{delegationAdvertiser: &otherAdvertiser}, 0, ErrDelegationMismatch},
		{"a corrupted org directory", delegationOverrides{corruptDirectory: true}, 0, ErrOrgDirectoryInvalid},
		{"a delegation where the org directory goes, and the directory in its place", delegationOverrides{swapDirectoryAndGrant: true}, 0, ErrOrgDirectoryInvalid},
		{"an expired delegation", delegationOverrides{delegationTTLMs: testMinute}, 10 * testMinute, ErrDelegationInvalid},
		{"an advertisement that outlives its delegation", delegationOverrides{delegationTTLMs: 2 * testMinute}, 0, ErrAuthorizationOutlived},
	} {
		advertisement, trust := delegationBundle(t, "acme/get_forecast_v1", c.overrides)
		wantRefusal(t, c.name, VerifyAuthorization(advertisement, trust, nowMs()+c.laterMs), c.want)
	}
}

// An org directory where the delegation goes is a record of the wrong type there
// too, refused as an invalid delegation once the directory itself holds.
func TestAnOrgDirectoryWhereTheDelegationGoesIsAnInvalidDelegation(t *testing.T) {
	advertisement, trust := delegationBundle(t, "acme/get_forecast_v1", delegationOverrides{})
	read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(advertisement.Record()))
	keys := keysFor(t)
	twice := signedAdvertisement(t, keys.node, "acme/get_forecast_v1", ProcedureAdvertisementOptions{
		Authorization: Authorization{Form: DelegationAuthorization, OrgDirectory: read.Authorization.OrgDirectory,
			ProcedureDelegation: read.Authorization.OrgDirectory},
		TTLMs: uint64(5 * testMinute),
	})
	wantRefusal(t, "an org directory in both places", VerifyAuthorization(twice, trust, nowMs()), ErrDelegationInvalid)
}

func TestTheDelegationNeedsTheRealmKey(t *testing.T) {
	advertisement, _ := delegationBundle(t, "acme/get_forecast_v1", delegationOverrides{})
	wantRefusal(t, "a delegation checked without a realm key",
		VerifyAuthorization(advertisement, Trust{Profile: profile.PQPure}, nowMs()), ErrNoRealmKey)
}

func TestAProcedureWithAnOrgNamespaceNeedsAnAuthorization(t *testing.T) {
	keys := keysFor(t)
	advertisement := signedAdvertisement(t, keys.node, "acme/x", ProcedureAdvertisementOptions{})
	wantRefusal(t, "acme/x without an authorization", VerifyAuthorization(advertisement, realmTrust(t), nowMs()), ErrNoAuthorization)
}

func TestAProcedureNameStartingWithASlashIsMalformed(t *testing.T) {
	advertisement, trust := delegationBundle(t, "/get_forecast_v1", delegationOverrides{})
	wantRefusal(t, "/get_forecast_v1", VerifyAuthorization(advertisement, trust, nowMs()), ErrMalformed)
}

// An authorization of any other form, a certificate chain among them, is
// unsupported, as verify_authorization/3 refuses it for 11.0.0; an org directory
// and a procedure delegation that are not both byte strings are malformed; and so
// is a record that is not a procedure advertisement, the zero Verified among
// them. An authorization that is not a map never reaches VerifyAuthorization,
// since Verify refuses the record that carries it.
func TestAnAuthorizationOfAnotherFormIsUnsupported(t *testing.T) {
	keys := keysFor(t)
	bundle, trust := delegationBundle(t, "acme/x", delegationOverrides{})
	read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(bundle.Record()))
	directory := bytesEntry("org_directory", read.Authorization.OrgDirectory)
	delegation := bytesEntry("procedure_delegation", read.Authorization.ProcedureDelegation)
	chain := valueEntry("certificate_chain", cbor.List([]cbor.Value{cbor.Bytes([]byte{1})}))
	for _, c := range []struct {
		name          string
		authorization cbor.Value
		want          error
	}{
		{"a certificate chain", cbor.Map([]cbor.MapEntry{chain}), ErrAuthorizationFormUnsupported},
		{"an empty certificate chain", cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain", cbor.List(nil))}), ErrAuthorizationFormUnsupported},
		{"the delegation form and a certificate chain", cbor.Map([]cbor.MapEntry{directory, delegation, chain}), ErrAuthorizationFormUnsupported},
		{"an org directory alone", cbor.Map([]cbor.MapEntry{directory}), ErrAuthorizationFormUnsupported},
		{"an empty map", cbor.Map(nil), ErrAuthorizationFormUnsupported},
		{"an org directory as text beside the delegation", cbor.Map([]cbor.MapEntry{textEntry("org_directory", "d"), delegation}), ErrMalformed},
	} {
		carrying := signedAdvertisementCarrying(t, keys.node, "acme/x", c.authorization)
		wantRefusal(t, c.name, VerifyAuthorization(carrying, trust, nowMs()), c.want)
	}
	entries, _ := advertisementPayload(keys.node.KeyID()).AsMap()
	notAMap := recordFields(t, TypeProcedureAdvertisement, cbor.Map(withEntry(entries, "authorization", cbor.List(nil))),
		nowMs(), 5*testMinute)
	_, err := Verify(signedByHand(t, label, notAMap, keys.node), profile.PQPure, nowMs())
	wantRefusal(t, "an authorization that is not a map, which Verify refuses first", err, ErrMalformed)
	node := must[Verified](t)(Verify(wireOf(t, signedNodeRecord(t, keys.node)), profile.PQPure, nowMs()))
	wantRefusal(t, "a node record", VerifyAuthorization(node, trust, nowMs()), ErrMalformed)
	wantRefusal(t, "the zero Verified", VerifyAuthorization(Verified{}, trust, nowMs()), ErrMalformed)
}

// A caller trusts its realm for a provider's authorization by the realm key
// alone: Trust holds the verifier's profile and the realm key, and no realm CA,
// as macula_record's trust holds realm_key alone.
func TestTrustHoldsOnlyTheProfileAndTheRealmKey(t *testing.T) {
	trust := reflect.TypeFor[Trust]()
	var fields []string
	for i := range trust.NumField() {
		fields = append(fields, trust.Field(i).Name)
	}
	if !slices.Equal(fields, []string{"Profile", "RealmKey"}) {
		t.Errorf("Trust holds %v, want Profile and RealmKey alone", fields)
	}
}

func TestAnOrgDirectoryReadsItsRealmOrgAndOrgKey(t *testing.T) {
	directory := unsignedRecord(t, TypeOrgDirectory, bytesEntry("realm_id", idBytes(0x11)), textEntry("org_name", "acme"),
		bytesEntry("org_key", idBytes(4)))
	if read := must[OrgDirectory](t)(ReadOrgDirectory(directory)); read != (OrgDirectory{RealmID: fill(0x11), OrgName: "acme", OrgKey: fill(4)}) {
		t.Errorf("read %+v, want realm 0x11, org acme and org key 0x04", read)
	}
	_, err := ReadOrgDirectory(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as an org directory", err, ErrMalformed)
}

func TestAProcedureDelegationNamesItsOrgKeyAndAdvertiser(t *testing.T) {
	authorization := authorizationKeysFor(t)
	orgKeyID := identity.KeyIDOf(authorization.org.PublicKey(), profile.PQPure)
	delegation := verifiedByHand(t, TypeProcedureDelegation, cbor.Map([]cbor.MapEntry{bytesEntry("org_key", orgKeyID[:]),
		bytesEntry("advertiser", idBytes(8))}), testHour, authorization.org)
	if read := must[ProcedureDelegation](t)(ReadProcedureDelegation(delegation)); read != (ProcedureDelegation{OrgKey: orgKeyID, Advertiser: fill(8)}) {
		t.Errorf("read %+v, want the org key id and advertiser 0x08", read)
	}
	_, err := ReadProcedureDelegation(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as a procedure delegation", err, ErrMalformed)
	fields := recordFields(t, TypeProcedureDelegation, cbor.Map([]cbor.MapEntry{bytesEntry("org_key", idBytes(3)),
		bytesEntry("advertiser", idBytes(8))}), nowMs(), testHour)
	_, err = Verify(signedByHand(t, label, fields, authorization.org), profile.PQPure, nowMs())
	wantRefusal(t, "a delegation whose org key is not its signer", err, ErrKeyIDMismatch)
}

// realmTrust is a trust holding the authorization tests' realm key.
func realmTrust(t *testing.T) Trust {
	t.Helper()
	return Trust{Profile: profile.PQPure, RealmKey: authorizationKeysFor(t).realm.PublicKey()}
}
