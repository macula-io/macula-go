package record

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_tombstone_tests at merge-11.0.0
// 871986a3: a tombstone takes the slot of the record it withdraws, names that
// record's type, version and slot fields, gives one of three reasons, is signed
// by the same key id, and expires no earlier than the withdrawn record. A Go
// key signs no realm, org or foundation record, so a tombstone of one is built
// by NewTombstone and signed by hand with an identity key, which a verifier
// accepts since it does not check a key's purpose. The payload refusals are
// rows of TestAPayloadItsTypeDoesNotAllowIsMalformed.

func TestANodeRecordTombstoneTakesTheNodeRecordsSlot(t *testing.T) {
	keys := keysFor(t)
	node := signedNodeRecord(t, keys.node)
	tombstone := must[Record](t)(Sign(must[Record](t)(NewTombstone(node, ReasonShutdown, TombstoneOptions{})), keys.node))
	key := must[[32]byte](t)(StorageKey(tombstone))
	if tombstone.Type != TypeTombstone || key != keys.node.KeyID() || key != must[[32]byte](t)(StorageKey(node)) {
		t.Errorf("a node record's tombstone of type %#02x is stored under %x, want a tombstone under the node_id %x",
			uint8(tombstone.Type), key, keys.node.KeyID())
	}
}

func TestThePayloadNamesTheWithdrawnTypeVersionAndReason(t *testing.T) {
	keys := keysFor(t)
	node := signedNodeRecord(t, keys.node)
	tombstone := must[Record](t)(NewTombstone(node, ReasonShutdown, TombstoneOptions{}))
	want := cbor.Map([]cbor.MapEntry{uintEntry("withdrawn_type", uint64(TypeNodeRecord)),
		bytesEntry("withdrawn_version", node.Version[:]), textEntry("reason", "shutdown")})
	if !sameValue(tombstone.Payload, want) {
		t.Errorf("the payload %v, want %v", tombstone.Payload, want)
	}
}

func TestDetailIsCarriedOnlyWhenGiven(t *testing.T) {
	keys := keysFor(t)
	node := signedNodeRecord(t, keys.node)
	tombstone := must[Record](t)(NewTombstone(node, ReasonMoved, TombstoneOptions{Detail: "to beam01"}))
	if detail, _ := payloadField(tombstone.Payload, "detail").AsText(); detail != "to beam01" {
		t.Errorf("detail %q, want to beam01", detail)
	}
	if _, present := must[Record](t)(NewTombstone(node, ReasonMoved, TombstoneOptions{})).Payload.Get("detail"); present {
		t.Error("a tombstone without a detail carries one")
	}
}

func TestOnlyShutdownMovedAndRevokedAreReasons(t *testing.T) {
	keys := keysFor(t)
	node := signedNodeRecord(t, keys.node)
	for _, reason := range []Reason{ReasonShutdown, ReasonMoved, ReasonRevoked} {
		signed := must[Record](t)(Sign(must[Record](t)(NewTombstone(node, reason, TombstoneOptions{})), keys.node))
		if _, err := Verify(wireOf(t, signed), profile.PQPure, nowMs()); err != nil {
			t.Errorf("a tombstone for %s: %v, want it verified", reason, err)
		}
	}
	_, err := NewTombstone(node, "retired", TombstoneOptions{})
	wantRefusal(t, "a tombstone retiring a record", err, ErrUnknownReason)
	_, err = NewTombstone(must[Record](t)(NewTombstone(node, ReasonShutdown, TombstoneOptions{})), ReasonShutdown, TombstoneOptions{})
	wantRefusal(t, "a tombstone of a tombstone", err, ErrTombstoneOfATombstone)
}

func TestATombstoneExpiresNoEarlierThanTheWithdrawnRecord(t *testing.T) {
	keys := keysFor(t)
	built := must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{TTLMs: uint64(2 * testDay)}))
	long := must[Record](t)(Sign(built, keys.node))
	if tombstone := must[Record](t)(NewTombstone(long, ReasonShutdown, TombstoneOptions{})); tombstone.ExpiresAt < long.ExpiresAt {
		t.Errorf("the tombstone expires at %d, before the record it withdraws at %d", tombstone.ExpiresAt, long.ExpiresAt)
	}
}

// A tombstone lives until the record it withdraws has expired plus the
// five-minute clock tolerance, so no replica serves the record again after the
// tombstone lapses. It signs within the withdrawn type's maximum plus twice that
// tolerance, since the record it withdraws may be created up to the tolerance
// ahead: here a tombstone for a procedure advertisement created four minutes
// ahead at its five-minute maximum signs and verifies, and one a millisecond
// past that bound is refused.
func TestATombstoneOutlivesTheWithdrawnRecordByTheClockTolerance(t *testing.T) {
	keys := keysFor(t)
	now := nowMs()
	advertisement := must[Record](t)(NewProcedureAdvertisement(keys.node.KeyID(), fill(0x11), "acme/echo_v1", fill(0x77),
		ProcedureAdvertisementOptions{}))
	advertisement.CreatedAt, advertisement.ExpiresAt = uint64(now+4*testMinute), uint64(now+9*testMinute)
	withdrawn := must[Record](t)(Sign(advertisement, keys.node))
	if _, err := Verify(wireOf(t, withdrawn), profile.PQPure, nowMs()); err != nil {
		t.Fatalf("verify the advertisement 4 minutes ahead: %v", err)
	}
	tombstone := must[Record](t)(NewTombstone(withdrawn, ReasonShutdown, TombstoneOptions{}))
	if tombstone.ExpiresAt < withdrawn.ExpiresAt+uint64(5*testMinute) {
		t.Errorf("the tombstone expires at %d, before the advertisement's expiry plus 5 minutes, %d",
			tombstone.ExpiresAt, withdrawn.ExpiresAt+uint64(5*testMinute))
	}
	signed := must[Record](t)(Sign(tombstone, keys.node))
	if signed.ExpiresAt != tombstone.ExpiresAt {
		t.Errorf("signing moved the tombstone's expiry from %d to %d", tombstone.ExpiresAt, signed.ExpiresAt)
	}
	if _, err := Verify(wireOf(t, signed), profile.PQPure, nowMs()); err != nil {
		t.Errorf("verify the tombstone: %v", err)
	}
	tombstone.ExpiresAt = tombstone.CreatedAt + uint64(15*testMinute) + 1
	_, err := Sign(tombstone, keys.node)
	wantRefusal(t, "sign the tombstone living 15 minutes and 1 ms", err, ErrLifetimeTooLong)
}

// A realm member endorsement's tombstone names the realm and the member, takes
// the endorsement's slot and key id, and needs the realm's key: an identity key
// may not sign it.
func TestAMemberEndorsementTombstoneNamesRealmAndMember(t *testing.T) {
	keys := keysFor(t)
	endorsement := verifiedByHand(t, TypeRealmMemberEndorsement, cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11)),
		bytesEntry("member_node", idBytes(2)), valueEntry("roles", cbor.List(nil))}), testHour, keys.node)
	tombstone := must[Record](t)(NewTombstone(endorsement, ReasonRevoked, TombstoneOptions{}))
	realmID, _ := payloadField(tombstone.Payload, "realm_id").AsBytes()
	member, _ := payloadField(tombstone.Payload, "member_node").AsBytes()
	if !bytes.Equal(realmID, idBytes(0x11)) || !bytes.Equal(member, idBytes(2)) {
		t.Errorf("the tombstone names realm %x and member %x, want the endorsement's", realmID, member)
	}
	verified := verifyTombstoneByHand(t, tombstone, keys.node)
	if must[[32]byte](t)(StorageKey(verified)) != must[[32]byte](t)(StorageKey(endorsement)) || verified.KeyID != endorsement.KeyID {
		t.Error("the endorsement's tombstone does not take its slot and key id")
	}
	_, err := Sign(tombstone, keys.node)
	wantRefusal(t, "sign an endorsement's tombstone with an identity key", err, ErrKeyPurposeMismatch)
}

func TestTombstonesShareTheSlotAndKeyIDOfWhatTheyWithdraw(t *testing.T) {
	keys := keysFor(t)
	keyID := identity.KeyIDOf(keys.node.PublicKey(), profile.PQPure)
	byHand := func(recordType Type, fields ...cbor.MapEntry) Record {
		return verifiedByHand(t, recordType, cbor.Map(fields), testHour, keys.node)
	}
	signed := func(r Record, err error) Record {
		return must[Record](t)(Sign(must[Record](t)(r, err), keys.node))
	}
	for _, c := range []struct {
		name      string
		withdrawn Record
		signable  bool
	}{
		{"an org directory", byHand(TypeOrgDirectory, bytesEntry("realm_id", idBytes(0x11)), textEntry("org_name", "acme"),
			bytesEntry("org_key", idBytes(4))), false},
		{"a procedure delegation", byHand(TypeProcedureDelegation, bytesEntry("org_key", keyID[:]), bytesEntry("advertiser", idBytes(5))), false},
		{"a foundation seed list", byHand(TypeFoundationSeedList), false},
		{"a foundation parameter", byHand(TypeFoundationParameter, textEntry("param_name", "max_hops"), uintEntry("param_value", 8)), false},
		{"a foundation T3 attestation", byHand(TypeFoundationT3Attestation, bytesEntry("station_id", idBytes(3))), false},
		{"a content announcement", signed(NewContentAnnouncement(keys.node.KeyID(), testContentID(), "quic://h:1", ContentAnnouncementOptions{})), true},
		{"a station endpoint", signed(NewStationEndpoint(4433, StationEndpointOptions{})), true},
		{"a domain record with a subject", signed(Envelope(DomainTypeMin, cbor.Map(nil), []byte("s1"), 0)), true},
		{"a domain record without one", signed(Envelope(DomainTypeMin+1, cbor.Map(nil), nil, 0)), true},
	} {
		tombstone := must[Record](t)(NewTombstone(c.withdrawn, ReasonRevoked, TombstoneOptions{}))
		verified := verifyTombstoneByHand(t, tombstone, keys.node)
		if c.signable {
			verified = must[Record](t)(Verify(wireOf(t, must[Record](t)(Sign(tombstone, keys.node))), profile.PQPure, nowMs()))
		}
		if must[[32]byte](t)(StorageKey(verified)) != must[[32]byte](t)(StorageKey(c.withdrawn)) || verified.KeyID != c.withdrawn.KeyID {
			t.Errorf("%s's tombstone does not take its slot and key id", c.name)
		}
	}
}

func TestReadTombstoneReturnsTheTypedPayload(t *testing.T) {
	keys := keysFor(t)
	endorsement := verifiedByHand(t, TypeRealmMemberEndorsement, cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11)),
		bytesEntry("member_node", idBytes(2))}), testHour, keys.node)
	tombstone := verifyTombstoneByHand(t, must[Record](t)(NewTombstone(endorsement, ReasonRevoked, TombstoneOptions{Detail: "left"})), keys.node)
	want := Tombstone{WithdrawnType: TypeRealmMemberEndorsement, WithdrawnVersion: endorsement.Version, Reason: ReasonRevoked,
		Detail: "left", RealmID: fill(0x11), MemberNode: fill(2)}
	if read := must[Tombstone](t)(ReadTombstone(tombstone)); !reflect.DeepEqual(read, want) {
		t.Errorf("read %+v, want %+v", read, want)
	}
	node := signedNodeRecord(t, keys.node)
	nodeTombstone := must[Record](t)(Sign(must[Record](t)(NewTombstone(node, ReasonShutdown, TombstoneOptions{})), keys.node))
	want = Tombstone{WithdrawnType: TypeNodeRecord, WithdrawnVersion: node.Version, Reason: ReasonShutdown}
	if read := must[Tombstone](t)(ReadTombstone(nodeTombstone)); !reflect.DeepEqual(read, want) {
		t.Errorf("read %+v, want %+v", read, want)
	}
	_, err := ReadTombstone(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as a tombstone", err, ErrMalformed)
	for _, c := range []struct {
		name      string
		withdrawn []cbor.MapEntry
	}{
		{"no withdrawn_type", nil},
		{"a withdrawn_type as text", []cbor.MapEntry{textEntry("withdrawn_type", "node_record")}},
		{"a withdrawn_type of 0", []cbor.MapEntry{uintEntry("withdrawn_type", 0)}},
		{"a withdrawn_type of 0x100", []cbor.MapEntry{uintEntry("withdrawn_type", 0x100)}},
		{"a withdrawn_type of 2^63", []cbor.MapEntry{uintEntry("withdrawn_type", 1<<63)}},
	} {
		_, err := ReadTombstone(Record{Type: TypeTombstone, Payload: cbor.Map(c.withdrawn)})
		wantRefusal(t, "read a tombstone with "+c.name, err, ErrMalformed)
	}
}

// ReadTombstone refuses a withdrawn_type that names no record type without
// echoing what a peer put there.
func TestReadTombstoneRefusesAWithdrawnTypeWithoutEchoingIt(t *testing.T) {
	echoed := bytes.Repeat([]byte("a peer's text "), 32)
	_, err := ReadTombstone(Record{Type: TypeTombstone, Payload: cbor.Map([]cbor.MapEntry{textEntry("withdrawn_type", string(echoed))})})
	wantRefusal(t, "read a tombstone whose withdrawn_type is text", err, ErrMalformed)
	if err != nil && bytes.Contains([]byte(err.Error()), []byte("a peer's text")) {
		t.Errorf("the refusal echoes the withdrawn_type: %v", err)
	}
}

// NewTombstone needs the slot fields of the record it withdraws, which
// macula's tombstone/3 raises on without.
func TestNewTombstoneNeedsTheWithdrawnRecordsSlotFields(t *testing.T) {
	withdrawn := Record{Type: TypeProcedureAdvertisement, Payload: cbor.Map([]cbor.MapEntry{bytesEntry("realm_id", idBytes(0x11))})}
	_, err := NewTombstone(withdrawn, ReasonShutdown, TombstoneOptions{})
	wantRefusal(t, "a tombstone of an advertisement without its procedure", err, ErrMalformed)
}

// verifyTombstoneByHand signs tombstone's tbs by hand with key and verifies it.
func verifyTombstoneByHand(t *testing.T, tombstone Record, key *identity.NodeKey) Record {
	t.Helper()
	return must[Record](t)(Verify(signedByHand(t, label, tbsFields(tombstone), key), profile.PQPure, nowMs()))
}
