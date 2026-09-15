package record

import (
	"encoding/hex"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_storage_key_tests at merge-11.0.0
// 871986a3: a node record is stored under the signer's node_id, and every other
// record under SHA-256("MACULA-PQ-STORAGE-KEY-V1" || 0x00 || type || fields),
// with a 32-byte id as it is and any other field length-prefixed. macula
// computed the vectors in Python with realm id 0x11..., member 0x22..., org key
// id 0x44..., advertiser 0x55..., station 0x77... and content id 02 55 88....
// Records a Go key cannot sign are built unsigned for the vectors, and signed
// by hand with an identity key where a slot names the signer, since a verifier
// does not check a key's purpose. A Go storage key is a [32]byte, so macula's
// test of its size has nothing to check.

func TestStorageKeyFunctionsMatchTheVectors(t *testing.T) {
	for _, c := range []struct {
		name string
		got  [32]byte
		want string
	}{
		{"procedure_key", ProcedureKey(fill(0x11), "acme/get_forecast_v1"), "efbcd93463f2cd8c2c00fd481ef4f2ad2948af8476f505d4e3aeb13b9e69e2bc"},
		{"content_key", must[[32]byte](t)(ContentKey(testContentID())), "c3860b4b53a5ad2ab73ec3c26ec8c228e46f2f0c123732b257ea5c8b93351138"},
		{"station_endpoint_key", StationEndpointKey(fill(0x77)), "745798b5c27ad23602e034732f508ab43dd623371133fb5425ee4f600e09bc6c"},
		{"org_directory_key", OrgDirectoryKey(fill(0x11), "acme"), "a0c45a66de0f7000a76726e424add18ef32014cbd106e9c72e8c8425c1282924"},
		{"procedure_delegation_key", ProcedureDelegationKey(fill(0x44), fill(0x55)), "011574703bed4c79df51f4cc53afcebd79a4401518b830aa12587950d1edfda4"},
	} {
		if want := vector(t, c.want); c.got != want {
			t.Errorf("%s: %x, want %x", c.name, c.got, want)
		}
	}
}

func TestRecordsNamedByTheirPayloadMatchTheVectors(t *testing.T) {
	realm := bytesEntry("realm_id", idBytes(0x11))
	for _, c := range []struct {
		name string
		r    Record
		want string
	}{
		{"a realm directory", unsignedRecord(t, TypeRealmDirectory, realm, textEntry("name", "io.macula"), bytesEntry("admin_key", idBytes(1))),
			"5ae659563813ed3f41b6ce4360c0397ddd46878fec0015beab4b2f7661a9fe29"},
		{"realm stations", unsignedRecord(t, TypeRealmStations, realm, valueEntry("stations", cbor.List(nil))),
			"d92cb1913d63777c2d7a4e7cb2177a978ecff041c00bb9567cf9fafd1e812341"},
		{"a realm member endorsement", unsignedRecord(t, TypeRealmMemberEndorsement, realm, bytesEntry("member_node", idBytes(0x22))),
			"d93b63bd8a0c04442b094aa046be12eb4e72e34156913e2e413904c580bfdc3b"},
		{"a procedure advertisement", must[Record](t)(NewProcedureAdvertisement(fill(0x55), fill(0x11), "acme/get_forecast_v1", fill(0x77),
			ProcedureAdvertisementOptions{})), "efbcd93463f2cd8c2c00fd481ef4f2ad2948af8476f505d4e3aeb13b9e69e2bc"},
		{"a foundation T3 attestation", unsignedRecord(t, TypeFoundationT3Attestation, bytesEntry("station_id", idBytes(0x77)),
			uintEntry("audit_date", 1789000000000)), "51c6fc4b520eed65bb556522be043366a888fb7c9a2d0915392378ca0adb8c31"},
		{"a content announcement", must[Record](t)(NewContentAnnouncement(fill(0x55), testContentID(), "quic://h:1", ContentAnnouncementOptions{})),
			"c3860b4b53a5ad2ab73ec3c26ec8c228e46f2f0c123732b257ea5c8b93351138"},
		{"an org directory", unsignedRecord(t, TypeOrgDirectory, realm, textEntry("org_name", "acme"), bytesEntry("org_key", idBytes(0x44))),
			"a0c45a66de0f7000a76726e424add18ef32014cbd106e9c72e8c8425c1282924"},
	} {
		if got, want := must[[32]byte](t)(StorageKey(c.r)), vector(t, c.want); got != want {
			t.Errorf("%s is stored under %x, want %x", c.name, got, want)
		}
	}
}

func TestANodeRecordIsStoredUnderItsNodeID(t *testing.T) {
	keys := keysFor(t)
	if got := must[[32]byte](t)(StorageKey(signedNodeRecord(t, keys.node))); got != keys.node.KeyID() {
		t.Errorf("a node record is stored under %x, want its node_id %x", got, keys.node.KeyID())
	}
	_, err := StorageKey(must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{})))
	wantRefusal(t, "the storage key of an unsigned node record", err, ErrUnsigned)
}

func TestAStationEndpointIsStoredUnderItsStationEndpointKey(t *testing.T) {
	keys := keysFor(t)
	signed := must[Record](t)(Sign(must[Record](t)(NewStationEndpoint(4433, StationEndpointOptions{})), keys.node))
	if got := must[[32]byte](t)(StorageKey(signed)); got != StationEndpointKey(keys.node.KeyID()) || got == keys.node.KeyID() {
		t.Errorf("a station endpoint is stored under %x, want its station endpoint key and not its node_id", got)
	}
}

func TestAProcedureDelegationIsStoredUnderItsOrgKeyIDAndAdvertiser(t *testing.T) {
	keys := keysFor(t)
	orgKeyID := identity.KeyIDOf(keys.node.PublicKey(), profile.PQPure)
	payload := cbor.Map([]cbor.MapEntry{bytesEntry("org_key", orgKeyID[:]), bytesEntry("advertiser", idBytes(0x55))})
	delegation := verifiedByHand(t, TypeProcedureDelegation, payload, testHour, keys.node)
	if got := must[[32]byte](t)(StorageKey(delegation)); got != ProcedureDelegationKey(orgKeyID, fill(0x55)) {
		t.Errorf("a procedure delegation is stored under %x, want its org key id and advertiser's key", got)
	}
}

func TestFoundationRecordsAreStoredPerSignerAndType(t *testing.T) {
	keys := keysFor(t)
	key := func(recordType Type, payload cbor.Value, signer *identity.NodeKey) [32]byte {
		return must[[32]byte](t)(StorageKey(verifiedByHand(t, recordType, payload, testHour, signer)))
	}
	parameter := func(name string) cbor.Value {
		return cbor.Map([]cbor.MapEntry{textEntry("param_name", name), uintEntry("param_value", 8)})
	}
	seeds := key(TypeFoundationSeedList, cbor.Map(nil), keys.node)
	oneSeed := cbor.Map([]cbor.MapEntry{valueEntry("seeds", cbor.List([]cbor.Value{cbor.Map([]cbor.MapEntry{bytesEntry("node_id", idBytes(1))})}))})
	switch {
	case key(TypeFoundationSeedList, oneSeed, keys.node) != seeds:
		t.Error("one signer's two seed lists are stored apart")
	case key(TypeFoundationSeedList, cbor.Map(nil), keys.other) == seeds:
		t.Error("two signers' seed lists share a slot")
	case key(TypeFoundationRealmTrustList, cbor.Map(nil), keys.node) == seeds:
		t.Error("one signer's seed list and realm trust list share a slot")
	case key(TypeFoundationParameter, parameter("max_hops"), keys.node) == key(TypeFoundationParameter, parameter("fanout"), keys.node):
		t.Error("one signer's two parameters share a slot")
	}
}

func TestDomainRecordsAreStoredPerSignerAndSubject(t *testing.T) {
	keys := keysFor(t)
	key := func(subject []byte, signer *identity.NodeKey) [32]byte {
		envelope := must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), subject, 0))
		return must[[32]byte](t)(StorageKey(must[Record](t)(Sign(envelope, signer))))
	}
	bare := key(nil, keys.node)
	switch {
	case key(nil, keys.node) != bare:
		t.Error("one signer's two domain records without a subject are stored apart")
	case key(nil, keys.other) == bare:
		t.Error("two signers' domain records share a slot")
	case key([]byte("s1"), keys.node) == bare:
		t.Error("a domain record with a subject shares the slot of one without")
	case key([]byte("s1"), keys.node) == key([]byte("s2"), keys.node):
		t.Error("two subjects share a slot")
	}
}

func TestContentKeyRefusesAContentIDWithAnotherTag(t *testing.T) {
	_, err := ContentKey(append([]byte{1, 0x55}, make([]byte, 32)...))
	wantRefusal(t, "the content key of a content id with tag 1", err, ErrNotAContentID)
}

// A storage key needs the fields its type's key derives from, and a tombstone's
// needs a withdrawn type from 1 to 255. macula's slot/4 raises on these, and Go
// refuses them.
func TestAStorageKeyNeedsTheFieldsItDerivesFrom(t *testing.T) {
	for _, c := range []struct {
		name string
		r    Record
		want error
	}{
		{"a realm directory without realm_id", unsignedRecord(t, TypeRealmDirectory), ErrMalformed},
		{"an advertisement whose procedure is bytes",
			unsignedRecord(t, TypeProcedureAdvertisement, bytesEntry("realm_id", idBytes(0x11)), bytesEntry("procedure", []byte("x"))), ErrMalformed},
		{"a content announcement with a tag 1 content id",
			unsignedRecord(t, TypeContentAnnouncement, bytesEntry("mcid", append([]byte{1, 0x55}, make([]byte, 48)...))), ErrNotAContentID},
		{"an unsigned station endpoint", must[Record](t)(NewStationEndpoint(1, StationEndpointOptions{})), ErrUnsigned},
		{"a type macula does not define", unsignedRecord(t, 0x07), ErrMalformed},
		{"a tombstone naming 0x100", unsignedRecord(t, TypeTombstone, uintEntry("withdrawn_type", 0x100)), ErrMalformed},
		{"a tombstone naming no type", unsignedRecord(t, TypeTombstone), ErrMalformed},
	} {
		_, err := StorageKey(c.r)
		wantRefusal(t, c.name, err, c.want)
	}
}

func vector(t *testing.T, s string) [32]byte {
	t.Helper()
	var key [32]byte
	if n, err := hex.Decode(key[:], []byte(s)); err != nil || n != 32 {
		t.Fatalf("the vector %s: %d bytes, %v", s, n, err)
	}
	return key
}

// unsignedRecord is an unsigned record of type t with the given payload fields,
// for the types a Go key cannot sign.
func unsignedRecord(t *testing.T, recordType Type, fields ...cbor.MapEntry) Record {
	t.Helper()
	return must[Record](t)(unsigned(recordType, cbor.Map(fields), 0))
}

// verifiedByHand is a record of type t with payload, living lifetimeMs from
// now, signed by hand with key and verified.
func verifiedByHand(t *testing.T, recordType Type, payload cbor.Value, lifetimeMs int64, key *identity.NodeKey) Record {
	t.Helper()
	now := nowMs()
	return must[Record](t)(Verify(signedByHand(t, label, recordFields(t, recordType, payload, now, lifetimeMs), key), profile.PQPure, now))
}
