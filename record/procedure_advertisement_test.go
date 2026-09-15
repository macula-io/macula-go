package record

import (
	"bytes"
	"slices"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_advertisement_tests at merge-11.0.0
// 871986a3 for the advertisement itself: the payload holds realm_id,
// procedure, advertiser_node, serving_station and, for a procedure with an org
// namespace, the provider authorization, which a storing verifier never parses.
// A Go key signs neither an org directory nor a delegation, so the
// authorization's records are stand-in bytes here. The payload refusals are
// rows of TestAPayloadItsTypeDoesNotAllowIsMalformed, and procedure_org/1 and
// verify_authorization/3 come with the authorization port.

func TestTheAdvertisementPayloadHoldsRealmIDProcedureAdvertiserAndServingStation(t *testing.T) {
	r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "_/posts.get_page", fill(0x77), ProcedureAdvertisementOptions{}))
	want := cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11)), textEntry("procedure", "_/posts.get_page"),
		bytesEntry("advertiser_node", idBytes(1)), bytesEntry("serving_station", idBytes(0x77))})
	if !sameValue(r.Payload, want) {
		t.Errorf("the payload %v, want %v", r.Payload, want)
	}
}

func TestTheAuthorizationTravelsInsideThePayload(t *testing.T) {
	delegation := Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("org directory"), ProcedureDelegation: []byte("delegation")}
	r := must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/get_forecast_v1", fill(0x77),
		ProcedureAdvertisementOptions{Authorization: delegation}))
	want := cbor.Map([]cbor.MapEntry{bytesEntry("org_directory", []byte("org directory")),
		bytesEntry("procedure_delegation", []byte("delegation"))})
	if got, _ := r.Payload.Get("authorization"); !sameValue(got, want) {
		t.Errorf("the delegation form travels as %v, want %v", got, want)
	}
	chain := Authorization{Form: CertificateChainAuthorization, CertificateChain: [][]byte{{1, 2, 3}, {4, 5}}}
	r = must[Record](t)(NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(2), ProcedureAdvertisementOptions{Authorization: chain}))
	want = cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain",
		cbor.List([]cbor.Value{cbor.Bytes([]byte{1, 2, 3}), cbor.Bytes([]byte{4, 5})}))})
	if got, _ := r.Payload.Get("authorization"); !sameValue(got, want) {
		t.Errorf("the certificate chain form travels as %v, want %v", got, want)
	}
}

func TestReadProcedureAdvertisementReturnsTheTypedPayload(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	delegation := Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("org directory"), ProcedureDelegation: []byte("delegation")}
	built := must[Record](t)(NewProcedureAdvertisement(nodeID, fill(0x11), "acme/get_forecast_v1", fill(0x77),
		ProcedureAdvertisementOptions{Authorization: delegation}))
	verified := must[Record](t)(Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs()))
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

// An authorization reads in the form it travels in, as read_authorization/1
// reads it: exactly org_directory and procedure_delegation, or exactly
// certificate_chain, and anything else as malformed. Go reads the forms' values
// as bytes, so a form holding another kind is malformed too. The builder writes
// no authorization in neither form.
func TestAnAuthorizationReadsInItsForm(t *testing.T) {
	advertisement := func(authorization cbor.Value) Record {
		entries, _ := advertisementPayload(fill(1)).AsMap()
		return Record{Type: TypeProcedureAdvertisement, Payload: cbor.Map(withEntry(entries, "authorization", authorization))}
	}
	directory, delegation := bytesEntry("org_directory", []byte("d")), bytesEntry("procedure_delegation", []byte("p"))
	chain := valueEntry("certificate_chain", cbor.List([]cbor.Value{cbor.Bytes([]byte{1})}))
	malformed := Authorization{Form: MalformedAuthorization}
	for _, c := range []struct {
		name          string
		authorization cbor.Value
		want          Authorization
	}{
		{"the delegation form", cbor.Map([]cbor.MapEntry{directory, delegation}),
			Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("d"), ProcedureDelegation: []byte("p")}},
		{"the certificate chain form", cbor.Map([]cbor.MapEntry{chain}),
			Authorization{Form: CertificateChainAuthorization, CertificateChain: [][]byte{{1}}}},
		{"an empty certificate chain", cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain", cbor.List(nil))}),
			Authorization{Form: CertificateChainAuthorization}},
		{"both forms", cbor.Map([]cbor.MapEntry{directory, delegation, chain}), malformed},
		{"an org directory alone", cbor.Map([]cbor.MapEntry{directory}), malformed},
		{"a delegation form holding text", cbor.Map([]cbor.MapEntry{textEntry("org_directory", "d"), delegation}), malformed},
		{"a certificate chain holding text",
			cbor.Map([]cbor.MapEntry{valueEntry("certificate_chain", cbor.List([]cbor.Value{cbor.Text("pem")}))}), malformed},
		{"an authorization that is not a map", cbor.List(nil), malformed},
	} {
		read := must[ProcedureAdvertisement](t)(ReadProcedureAdvertisement(advertisement(c.authorization)))
		if !sameAuthorization(read.Authorization, c.want) {
			t.Errorf("%s reads as %+v, want %+v", c.name, read.Authorization, c.want)
		}
	}
	_, err := NewProcedureAdvertisement(fill(1), fill(0x11), "acme/x", fill(2), ProcedureAdvertisementOptions{Authorization: malformed})
	wantRefusal(t, "build an advertisement with an authorization in neither form", err, ErrMalformed)
}

func sameAuthorization(a, b Authorization) bool {
	return a.Form == b.Form && bytes.Equal(a.OrgDirectory, b.OrgDirectory) &&
		bytes.Equal(a.ProcedureDelegation, b.ProcedureDelegation) && slices.EqualFunc(a.CertificateChain, b.CertificateChain, bytes.Equal)
}
