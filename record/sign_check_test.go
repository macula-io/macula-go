package record

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// Sign runs the verifier's own tbs and payload rules before it signs, as
// macula_record's sign/2 does, so it never signs a record Verify would refuse
// for anything but its clock. Each case is refused for its first fault in
// Sign's order: purpose, lifetime, named signer, then the tbs and payload. It
// mirrors sign_refuses_a_record_verify_would_refuse_test_ in macula's
// macula_record_tests at merge-11.0.0 24b1705a, green at 81e2eca1. Its row for a
// version that is not 16 bytes has no Go form, since Record.Version is [16]byte.
func TestSignRefusesARecordAVerifierWouldRefuse(t *testing.T) {
	keys := keysFor(t)
	withdrawing := func(withdrawn uint64, reason string, slot ...cbor.MapEntry) Record {
		payload := append([]cbor.MapEntry{uintEntry("withdrawn_type", withdrawn), bytesEntry("withdrawn_version", make([]byte, 16)),
			textEntry("reason", reason)}, slot...)
		return must[Record](t)(unsigned(TypeTombstone, cbor.Map(payload), uint64(10*testMinute)))
	}
	nodeWithSubject := must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{}))
	nodeWithSubject.Subject = []byte("s1")
	emptySubject := must[Record](t)(Envelope(DomainTypeMin, cbor.Map(nil), nil, 0))
	emptySubject.Subject = []byte{}
	for _, c := range []struct {
		name string
		r    Record
		want error
	}{
		{"a tombstone withdrawing type 300", withdrawing(300, "shutdown"), ErrMalformed},
		{"a tombstone of a tombstone, whose withdrawn type no key signs", withdrawing(uint64(TypeTombstone), "shutdown"), ErrKeyPurposeMismatch},
		{"a tombstone whose slot lacks its withdrawn type's procedure",
			withdrawing(uint64(TypeProcedureAdvertisement), "shutdown", bytesEntry("realm_id", idBytes(0x11))), ErrMalformed},
		{"a tombstone giving a reason no rule names", withdrawing(uint64(DomainTypeMin), "retired"), ErrMalformed},
		{"a domain record with an empty subject", emptySubject, ErrMalformed},
		{"a node record carrying a subject", nodeWithSubject, ErrMalformed},
	} {
		_, err := Sign(c.r, keys.node)
		wantRefusal(t, "sign "+c.name, err, c.want)
	}
}

// Sign decodes the tbs it would sign under the decoding rule, as a verifier
// decodes the tbs it receives, before it reads that tbs and its payload, so it
// signs no payload the rule refuses: one nested past cbor.MaxNestingDepth, a
// nested map with a duplicate or byte-string key, or more items than
// cbor.MaxElements within 256 KiB.
func TestSignRefusesATBSTheDecodingRuleRefuses(t *testing.T) {
	keys := keysFor(t)
	deep := cbor.Int(1)
	for range cbor.MaxNestingDepth {
		deep = cbor.List([]cbor.Value{deep})
	}
	many := make([]cbor.Value, cbor.MaxElements)
	for i := range many {
		many[i] = cbor.Int(0)
	}
	for _, c := range []struct {
		name  string
		entry cbor.MapEntry
	}{
		{"a payload nested past the decoding rule's depth", valueEntry("deep", deep)},
		{"a nested map with a duplicate key", valueEntry("inner", cbor.Map([]cbor.MapEntry{uintEntry("a", 1), uintEntry("a", 2)}))},
		{"a nested map with a byte-string key", valueEntry("inner", cbor.Map([]cbor.MapEntry{{Key: cbor.Bytes([]byte("a")), Val: cbor.Int(1)}}))},
		{"a payload of more items than the decoding rule reads", valueEntry("many", cbor.List(many))},
	} {
		r := must[Record](t)(Envelope(DomainTypeMin, cbor.Map([]cbor.MapEntry{c.entry}), nil, 0))
		_, err := Sign(r, keys.node)
		wantRefusal(t, "sign "+c.name, err, ErrMalformed)
	}
}

// Every Go builder's record still signs and verifies with Sign's check, as
// every_builder_record_signs_and_verifies_test has it at 24b1705a.
func TestEveryBuilderSignsAndVerifies(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	lat := 50.8
	node := must[Record](t)(NewNodeRecord(nodeID, [][32]byte{fill(0x11)}, 3, NodeRecordOptions{Lat: &lat, Kind: "station"}))
	size := uint64(10)
	for _, c := range []struct {
		name string
		r    Record
	}{
		{"a node record", node},
		{"a procedure advertisement", must[Record](t)(NewProcedureAdvertisement(nodeID, fill(0x11), "acme/x", fill(2), ProcedureAdvertisementOptions{
			Authorization: Authorization{Form: DelegationAuthorization, OrgDirectory: []byte("d"), ProcedureDelegation: []byte("p")},
		}))},
		{"a content announcement", must[Record](t)(NewContentAnnouncement(nodeID, testContentID(), "quic://h:1",
			ContentAnnouncementOptions{Name: "a.bin", Size: &size}))},
		{"a station endpoint", must[Record](t)(NewStationEndpoint(4433, StationEndpointOptions{HostAdvertised: []string{"beam00.lab"}, ALPN: "macula/1"}))},
		{"a domain record with a subject", must[Record](t)(Envelope(DomainTypeMin, cbor.Map([]cbor.MapEntry{uintEntry("fact", 1)}), []byte("s1"), 0))},
		{"a tombstone of a node record", must[Record](t)(NewTombstone(must[Record](t)(Sign(node, keys.node)), ReasonMoved, TombstoneOptions{Detail: "to beam01"}))},
	} {
		signed, err := Sign(c.r, keys.node)
		if err != nil {
			t.Errorf("sign %s: %v, want it signed", c.name, err)
			continue
		}
		if _, err := Verify(wireOf(t, signed), profile.PQPure, nowMs()); err != nil {
			t.Errorf("verify %s: %v, want it verified", c.name, err)
		}
	}
}
