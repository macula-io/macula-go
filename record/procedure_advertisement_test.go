package record

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_advertisement_tests at merge-11.0.0
// 2d2c2ecb for the advertisement itself: the payload holds realm_id, procedure,
// advertiser_node, serving_station and, for a procedure with an org namespace,
// the provider authorization, an org directory and a procedure delegation,
// which a storing verifier never parses. macula 11.0.0 has no other form: its
// builder builds none, and its reader reads any other authorization map, a
// certificate chain among them, as unsupported. A Go key signs neither an org
// directory nor a delegation, so the authorization's records are stand-in
// bytes here. The payload refusals are rows of
// TestAPayloadItsTypeDoesNotAllowIsMalformed, and procedure_org/1 and
// verify_authorization/3 are in provider_authorization_test.go.

func TestTheAdvertisementPayloadHoldsRealmIDProcedureAdvertiserAndServingStation(t *testing.T) {
	r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "_/posts.get_page", fill(0x77), ProcedureAdvertisementOptions{}))
	want := cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11)), textEntry("procedure", "_/posts.get_page"),
		bytesEntry("advertiser_node", idBytes(1)), bytesEntry("serving_station", idBytes(0x77))})
	if !sameValue(r.Payload, want) {
		t.Errorf("the payload %v, want %v", r.Payload, want)
	}
}

// The delegation form travels inside the payload, and the builder builds no
// other: the unsupported form is ErrAuthorizationFormUnsupported, and the
// malformed form ErrMalformed.
func TestTheAuthorizationTravelsInsideThePayload(t *testing.T) {
	delegation := Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("org directory"), ProcedureDelegation: []byte("delegation")}
	r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/get_forecast_v1", fill(0x77),
		ProcedureAdvertisementOptions{Authorization: delegation}))
	want := cbor.Map([]cbor.MapEntry{bytesEntry("org_directory", []byte("org directory")),
		bytesEntry("procedure_delegation", []byte("delegation"))})
	if got, _ := r.Payload.Get("authorization"); !sameValue(got, want) {
		t.Errorf("the delegation form travels as %v, want %v", got, want)
	}
	for _, c := range []struct {
		name string
		form AuthorizationForm
		want error
	}{
		{"the unsupported form", UnsupportedAuthorization, ErrAuthorizationFormUnsupported},
		{"the malformed form", MalformedAuthorization, ErrMalformed},
	} {
		_, err := NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(2),
			ProcedureAdvertisementOptions{Authorization: Authorization{Form: c.form}})
		wantRefusal(t, "build an advertisement with "+c.name, err, c.want)
	}
}

func TestReadProcedureAdvertisementReturnsTheTypedPayload(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	delegation := Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("org directory"), ProcedureDelegation: []byte("delegation")}
	built := must[Record](t)(NewProcedureAdvertisement(nodeID, fill(0x11), "acme/get_forecast_v1", fill(0x77),
		ProcedureAdvertisementOptions{Authorization: delegation}))
	verified := must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs())).Record()
	read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(verified))
	if read.RealmID != fill(0x11) || read.Procedure != "acme/get_forecast_v1" || read.AdvertiserNode != nodeID ||
		read.ServingStation != fill(0x77) || !sameAuthorization(read.Authorization, delegation) {
		t.Errorf("read %+v, want the advertisement as built", read)
	}
	bare := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "echo.ping", fill(2), ProcedureAdvertisementOptions{}))
	if read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(bare)); read.Authorization.Form != NoAuthorization {
		t.Errorf("an advertisement without an authorization reads %+v, want none", read.Authorization)
	}
	_, err := ReadProcedureAdvertisement(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as a procedure advertisement", err, ErrMalformed)
}

func TestSignRefusesAnAdvertisementForAnotherAdvertiser(t *testing.T) {
	keys := keysFor(t)
	_, err := Sign(must[Record](t)(NewProcedureAdvertisement(fill(9), fill(0x11), "x.y", fill(2), ProcedureAdvertisementOptions{})), keys.node)
	wantRefusal(t, "an advertisement naming another advertiser", err, ErrKeyIDMismatch)
}

func TestAStoringVerifierNeverParsesTheAuthorization(t *testing.T) {
	keys := keysFor(t)
	opaque := Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("not a record"), ProcedureDelegation: []byte{}}
	built := must[Record](t)(NewProcedureAdvertisement(keys.node.KeyID(), fill(0x11), "_/x", fill(2),
		ProcedureAdvertisementOptions{Authorization: opaque}))
	if _, err := Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs()); err != nil {
		t.Errorf("verify an advertisement whose authorization holds no records: %v, want it verified", err)
	}
}

// A procedure advertisement built without a ttl lives its type's maximum, five
// minutes, as macula_record_tests has it.
func TestAProcedureAdvertisementDefaultsToItsMaximumLifetime(t *testing.T) {
	r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/echo_v1", fill(0x77), ProcedureAdvertisementOptions{}))
	if lived := int64(r.ExpiresAt - r.CreatedAt); lived != 5*testMinute {
		t.Errorf("an advertisement built without a ttl lives %d ms, want 5 minutes", lived)
	}
}

// An authorization reads in its form as read_authorization/1 reads it: exactly
// org_directory and procedure_delegation, both byte strings, is the delegation
// form; those two fields not both byte strings, or a value that is not a map,
// is malformed; and any other map, a certificate chain among them, is the
// unsupported form.
func TestAnAuthorizationReadsInItsForm(t *testing.T) {
	advertisement := func(authorization cbor.Value) Record {
		entries, _ := advertisementPayload(fill(1)).AsMap()
		return Record{Type: TypeProcedureAdvertisement, Payload: cbor.Map(withEntry(entries, "authorization", authorization))}
	}
	directory, delegation := bytesEntry("org_directory", []byte("d")), bytesEntry("procedure_delegation", []byte("p"))
	chain := valueEntry("certificate_chain", cbor.List([]cbor.Value{cbor.Bytes([]byte{1})}))
	unsupported, malformed := Authorization{Form: UnsupportedAuthorization}, Authorization{Form: MalformedAuthorization}
	for _, c := range []struct {
		name          string
		authorization cbor.Value
		want          Authorization
	}{
		{"the delegation form", cbor.Map([]cbor.MapEntry{directory, delegation}),
			Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("d"), ProcedureDelegation: []byte("p")}},
		{"a certificate chain", cbor.Map([]cbor.MapEntry{chain}), unsupported},
		{"an empty certificate chain", cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain", cbor.List(nil))}), unsupported},
		{"the delegation form and a certificate chain", cbor.Map([]cbor.MapEntry{directory, delegation, chain}), unsupported},
		{"an org directory alone", cbor.Map([]cbor.MapEntry{directory}), unsupported},
		{"an org directory beside a certificate chain", cbor.Map([]cbor.MapEntry{directory, chain}), unsupported},
		{"an empty map", cbor.Map(nil), unsupported},
		{"a delegation form holding text", cbor.Map([]cbor.MapEntry{textEntry("org_directory", "d"), delegation}), malformed},
		{"an authorization that is not a map", cbor.List(nil), malformed},
	} {
		read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(advertisement(c.authorization)))
		if !sameAuthorization(read.Authorization, c.want) {
			t.Errorf("%s reads as %+v, want %+v", c.name, read.Authorization, c.want)
		}
	}
}

func sameAuthorization(a, b Authorization) bool {
	return a.Form == b.Form && bytes.Equal(a.OrgDirectory, b.OrgDirectory) && bytes.Equal(a.ProcedureDelegation, b.ProcedureDelegation)
}
