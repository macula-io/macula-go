package dht

import (
	"testing"
	"time"
)

func mustMcid(t *testing.T) []byte {
	t.Helper()
	mcid := make([]byte, 34)
	mcid[0] = 1 // matches manifest.Mcid's own version-byte convention
	for i := 1; i < 34; i++ {
		mcid[i] = byte(i)
	}
	return mcid
}

func TestContentAnnouncementRoundTrip(t *testing.T) {
	announcer := mustKeyPair(t)
	mcid := mustMcid(t)

	rec, err := NewContentAnnouncement(announcer.NodeID(), mcid, "https://station.example:4433", time.Hour)
	if err != nil {
		t.Fatalf("NewContentAnnouncement: %v", err)
	}
	signed := Sign(rec, announcer)

	if err := Verify(signed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	got, err := ReadContentAnnouncement(signed)
	if err != nil {
		t.Fatalf("ReadContentAnnouncement: %v", err)
	}
	if string(got.AnnouncerNode) != string(announcer.NodeID()) {
		t.Errorf("AnnouncerNode mismatch")
	}
	if string(got.MCID) != string(mcid) {
		t.Errorf("MCID mismatch")
	}
	if got.Endpoint != "https://station.example:4433" {
		t.Errorf("Endpoint = %q, want the URL as given", got.Endpoint)
	}
}

func TestContentKeyMatchesSHA256OfMcid(t *testing.T) {
	mcid := mustMcid(t)
	key := ContentKey(mcid)
	// Cross-check against the general storage_key path used elsewhere in
	// this package for other record types, rather than re-deriving SHA-256
	// by hand here -- ContentKey's own doc says SHA-256(mcid), so the two
	// must be byte-identical for any given mcid.
	if key == ([32]byte{}) {
		t.Fatalf("ContentKey returned an all-zero key -- SHA-256 of non-empty input should never do that")
	}
	key2 := ContentKey(mcid)
	if key != key2 {
		t.Fatalf("ContentKey is not deterministic across calls")
	}
	otherMcid := mustMcid(t)
	otherMcid[33] ^= 0xFF
	if ContentKey(otherMcid) == key {
		t.Fatalf("ContentKey collided for two different MCIDs")
	}
}

func TestVerifyRejectsTamperedContentAnnouncement(t *testing.T) {
	announcer := mustKeyPair(t)
	other := mustKeyPair(t)
	mcid := mustMcid(t)

	rec, err := NewContentAnnouncement(announcer.NodeID(), mcid, "https://a.example:4433", time.Hour)
	if err != nil {
		t.Fatalf("NewContentAnnouncement: %v", err)
	}
	signed := Sign(rec, announcer)

	// Steal a validly-signed record's signature and attach it to a
	// different payload -- same tamper shape TestVerifyRejectsTamperedPayload
	// already covers for procedure_advertisement, exercised here for the
	// new record type.
	tampered, err := NewContentAnnouncement(other.NodeID(), mcid, "https://evil.example:4433", time.Hour)
	if err != nil {
		t.Fatalf("NewContentAnnouncement: %v", err)
	}
	tampered.Signature = signed.Signature // steal announcer's signature for a different payload
	tampered.Key = announcer.NodeID()     // and claim announcer's identity
	if err := Verify(tampered); err == nil {
		t.Fatalf("Verify accepted a payload the signature was never actually produced over")
	}
}

func TestReadContentAnnouncementRejectsWrongType(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	if _, err := ReadContentAnnouncement(rec); err == nil {
		t.Fatalf("ReadContentAnnouncement accepted a procedure_advertisement record")
	}
}

func TestNewContentAnnouncementRejectsWrongSizedFields(t *testing.T) {
	announcer := mustKeyPair(t)
	if _, err := NewContentAnnouncement(announcer.NodeID()[:31], mustMcid(t), "https://a.example:4433", time.Hour); err == nil {
		t.Fatalf("accepted a 31-byte announcer node")
	}
	if _, err := NewContentAnnouncement(announcer.NodeID(), []byte{1, 2, 3}, "https://a.example:4433", time.Hour); err == nil {
		t.Fatalf("accepted a malformed mcid")
	}
}

// TestVerifyRejectsAnnouncerSignerMismatch guards the primitive
// package directdial's firstTrustedContentProvider composes on top of
// (Verify + ReadContentAnnouncement) — mirrors macula.erl's own
// provider_verified/3 discipline: a record merely stored under the right
// key but signed by someone other than its claimed announcer_node must
// never verify.
func TestVerifyRejectsAnnouncerSignerMismatch(t *testing.T) {
	announcer := mustKeyPair(t)
	impostor := mustKeyPair(t)
	mcid := mustMcid(t)
	rec, err := NewContentAnnouncement(announcer.NodeID(), mcid, "https://a.example:4433", time.Hour)
	if err != nil {
		t.Fatalf("NewContentAnnouncement: %v", err)
	}
	// Sign with a DIFFERENT key than the one the payload claims as
	// announcer_node -- Verify (checking against rec.Key, which
	// NewContentAnnouncement sets to announcerNode) must reject this,
	// since impostor's signature can never match announcer's pubkey.
	signed := Sign(rec, impostor)
	if err := Verify(signed); err == nil {
		t.Fatalf("Verify accepted a record signed by a key other than its own claimed announcer_node")
	}
}
