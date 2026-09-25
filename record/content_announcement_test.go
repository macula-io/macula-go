package record

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record content announcement at 12.6.0
// (D27): the announcer signs its own announcement of a tag 2 content id,
// naming the realm, the station it is reachable through and its content
// procedure, and the announcement is stored under the content id's storage
// key, so every announcer of one content id shares a slot. A verifier's
// refusals of a malformed payload are rows of
// TestAPayloadItsTypeDoesNotAllowIsMalformed.

// testProcedure is a content procedure in a node's own namespace.
const testProcedure = "~abababababababababababababababababababababababababababababababab/content_v1"

// testContentID is a tag 2 content id: the tag, codec 0x55 and 48 hash bytes of
// 0x88.
func testContentID() []byte {
	return append([]byte{2, 0x55}, bytes.Repeat([]byte{0x88}, 48)...)
}

func TestTheAnnouncementPayloadNamesAnnouncerContentIDAndWhereItIsServed(t *testing.T) {
	r := must[Record](t)(NewContentAnnouncement(fill(1), testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure}))
	want := cbor.Map([]cbor.MapEntry{bytesEntry("announcer_node", idBytes(1)), bytesEntry("mcid", testContentID()),
		bytesEntry("realm_id", idBytes(3)), bytesEntry("serving_station", idBytes(4)), textEntry("procedure", testProcedure)})
	if !sameValue(r.Payload, want) {
		t.Errorf("the payload %v, want %v", r.Payload, want)
	}
}

func TestNewContentAnnouncementRefusesAnEmptyProcedure(t *testing.T) {
	_, err := NewContentAnnouncement(fill(1), testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4)})
	wantRefusal(t, "an announcement without a procedure", err, ErrMalformed)
}

func TestMetadataIsCarriedWhenGiven(t *testing.T) {
	size, chunks := uint64(1048576), uint64(4)
	r := must[Record](t)(NewContentAnnouncement(fill(1), testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure, Name: "report.pdf", Size: &size, ChunkCount: &chunks}))
	name, _ := payloadField(r.Payload, "name").AsText()
	gotSize, _ := payloadField(r.Payload, "size").AsInt64()
	gotChunks, _ := payloadField(r.Payload, "chunk_count").AsInt64()
	if name != "report.pdf" || gotSize != 1048576 || gotChunks != 4 {
		t.Errorf("name %q, size %d and chunk_count %d, want report.pdf, 1048576 and 4", name, gotSize, gotChunks)
	}
}

func TestNewContentAnnouncementRefusesAContentIDThatIsNotTag2SHA384(t *testing.T) {
	for _, c := range []struct {
		name string
		mcid []byte
	}{
		{"a tag 2 content id of 34 bytes", append([]byte{2, 0x55}, make([]byte, 32)...)},
		{"a content id with tag 1", append([]byte{1, 0x55}, make([]byte, 48)...)},
	} {
		_, err := NewContentAnnouncement(fill(1), c.mcid, ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure})
		wantRefusal(t, c.name, err, ErrNotAContentID)
	}
}

func TestASignedAnnouncementVerifies(t *testing.T) {
	keys := keysFor(t)
	unsignedAnnouncement := must[Record](t)(NewContentAnnouncement(keys.node.KeyID(), testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure}))
	if _, err := Verify(wireOf(t, must[Record](t)(Sign(unsignedAnnouncement, keys.node))), profile.PQPure, nowMs()); err != nil {
		t.Errorf("verify a signed announcement: %v", err)
	}
}

func TestSignRefusesAnAnnouncementForAnotherAnnouncer(t *testing.T) {
	keys := keysFor(t)
	_, err := Sign(must[Record](t)(NewContentAnnouncement(fill(9), testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure})), keys.node)
	wantRefusal(t, "an announcement naming another announcer", err, ErrKeyIDMismatch)
}

func TestEveryAnnouncerOfOneContentIDSharesItsSlot(t *testing.T) {
	key := func(announcer [32]byte) [32]byte {
		announcement := must[Record](t)(NewContentAnnouncement(announcer, testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure}))
		return must[[32]byte](t)(StorageKey(announcement))
	}
	contentKey := must[[32]byte](t)(ContentKey(testContentID()))
	if first, second := key(fill(1)), key(fill(2)); first != contentKey || second != contentKey {
		t.Errorf("two announcers' announcements are stored under %x and %x, want the content key %x", first, second, contentKey)
	}
}

func TestContentKeyRefusesAContentIDOfTheWrongSize(t *testing.T) {
	_, err := ContentKey(append([]byte{2, 0x55}, make([]byte, 32)...))
	wantRefusal(t, "the content key of a 34-byte content id", err, ErrNotAContentID)
}

func TestReadContentAnnouncementReturnsTheTypedPayload(t *testing.T) {
	keys := keysFor(t)
	nodeID := keys.node.KeyID()
	size, chunks := uint64(10), uint64(1)
	full := must[Record](t)(NewContentAnnouncement(nodeID, testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure, Name: "a.bin", Size: &size, ChunkCount: &chunks}))
	verified := must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(full, keys.node))), profile.PQPure, nowMs())).Record()
	read := must[ContentAnnouncement](t)(ReadContentAnnouncement(verified))
	switch {
	case read.AnnouncerNode != nodeID || !bytes.Equal(read.MCID, testContentID()):
		t.Errorf("announcer %x and content id %x, want the signer and the content id", read.AnnouncerNode, read.MCID)
	case read.RealmID != fill(3) || read.ServingStation != fill(4) || read.Procedure != testProcedure:
		t.Errorf("realm %x, serving station %x and procedure %q, want the ones announced", read.RealmID, read.ServingStation, read.Procedure)
	case read.Name != "a.bin" || read.Size == nil || *read.Size != 10 || read.ChunkCount == nil || *read.ChunkCount != 1:
		t.Errorf("name %q, size %v and chunk_count %v, want a.bin, 10 and 1", read.Name, read.Size, read.ChunkCount)
	}
	bare := must[Record](t)(NewContentAnnouncement(nodeID, testContentID(), ContentAnnouncementOptions{RealmID: fill(3), ServingStation: fill(4), Procedure: testProcedure}))
	if read := must[ContentAnnouncement](t)(ReadContentAnnouncement(bare)); read.Name != "" || read.Size != nil || read.ChunkCount != nil {
		t.Errorf("an announcement without metadata reads name %q, size %v and chunk_count %v, want none", read.Name, read.Size, read.ChunkCount)
	}
	_, err := ReadContentAnnouncement(Record{Type: TypeNodeRecord, Payload: cbor.Map(nil)})
	wantRefusal(t, "read a node record as a content announcement", err, ErrMalformed)
}
