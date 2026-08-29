package dht

import (
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/identity"
)

func mustKeyPair(t *testing.T) identity.KeyPair {
	t.Helper()
	kp, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return kp
}

func TestSignVerifyRoundTrip(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	signed := Sign(rec, advertiser)

	if len(signed.Signature) != 64 {
		t.Fatalf("Signature length = %d, want 64", len(signed.Signature))
	}
	if err := Verify(signed); err != nil {
		t.Fatalf("Verify(freshly signed record) = %v, want nil", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	otherStation := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	signed := Sign(rec, advertiser)

	// Swap in a different serving_station after signing, without
	// re-signing -- an attacker rewriting the advertisement to redirect
	// callers to a station of their choosing. Verify must reject this.
	tampered, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", otherStation.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	tampered.Signature = signed.Signature

	if err := Verify(tampered); err == nil {
		t.Fatalf("Verify(tampered payload with original signature) = nil, want an error")
	}
}

func TestVerifyRejectsWrongSigner(t *testing.T) {
	advertiser := mustKeyPair(t)
	impostor := mustKeyPair(t)
	station := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	// Sign with a different key than the record's own `Key` field claims.
	signed := Sign(rec, impostor)

	if err := Verify(signed); err == nil {
		t.Fatalf("Verify(record signed by a different identity than its Key field) = nil, want an error")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	rec.ExpiresAt = time.Now().Add(-time.Minute).UnixMilli()
	signed := Sign(rec, advertiser)

	if err := Verify(signed); err != ErrExpired {
		t.Fatalf("Verify(expired record) = %v, want ErrExpired", err)
	}
}

func TestCanonicalUnsignedIsDeterministic(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	a := canonicalUnsigned(rec)
	b := canonicalUnsigned(rec)
	if string(a) != string(b) {
		t.Fatalf("canonicalUnsigned is not deterministic across repeated calls on the same record")
	}
}

func TestReadProcedureAdvertisementRoundTrip(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	const uri = "0000/hecate_mail.initiate_mailbox"

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), uri, station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	adv, err := ReadProcedureAdvertisement(rec)
	if err != nil {
		t.Fatalf("ReadProcedureAdvertisement: %v", err)
	}
	if adv.ProcedureURI != uri {
		t.Errorf("ProcedureURI = %q, want %q", adv.ProcedureURI, uri)
	}
	if string(adv.AdvertiserNode) != string(advertiser.NodeID()) {
		t.Errorf("AdvertiserNode mismatch")
	}
	if string(adv.ServingStation) != string(station.NodeID()) {
		t.Errorf("ServingStation mismatch")
	}
}

func TestRecordRPCValueRoundTrip(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), "0000/math.add_v1", station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	signed := Sign(rec, advertiser)

	wire := signed.toRPCValue()
	back, err := recordFromRPCValue(wire)
	if err != nil {
		t.Fatalf("recordFromRPCValue: %v", err)
	}

	if back.Type != signed.Type {
		t.Errorf("Type = %d, want %d", back.Type, signed.Type)
	}
	if string(back.Key) != string(signed.Key) {
		t.Errorf("Key mismatch")
	}
	if string(back.Version) != string(signed.Version) {
		t.Errorf("Version mismatch")
	}
	if back.CreatedAt != signed.CreatedAt || back.ExpiresAt != signed.ExpiresAt {
		t.Errorf("timestamps mismatch: got (%d,%d), want (%d,%d)", back.CreatedAt, back.ExpiresAt, signed.CreatedAt, signed.ExpiresAt)
	}
	if string(back.Signature) != string(signed.Signature) {
		t.Errorf("Signature mismatch")
	}
	// The round trip must also still verify -- a lossy encode/decode of
	// the payload (e.g. dropping the byte-string/text-string distinction
	// between advertiser_node and procedure_uri) would silently produce a
	// record whose signature no longer checks out.
	if err := Verify(back); err != nil {
		t.Fatalf("Verify(record round-tripped through RPC wire encoding) = %v, want nil", err)
	}
	advBack, err := ReadProcedureAdvertisement(back)
	if err != nil {
		t.Fatalf("ReadProcedureAdvertisement(round-tripped record): %v", err)
	}
	if advBack.ProcedureURI != "0000/math.add_v1" {
		t.Errorf("ProcedureURI after round trip = %q", advBack.ProcedureURI)
	}
}

func TestProcedureKeyMatchesStorageKeyDerivation(t *testing.T) {
	advertiser := mustKeyPair(t)
	station := mustKeyPair(t)
	const uri = "0000/math.add_v1"

	rec, err := NewProcedureAdvertisement(advertiser.NodeID(), uri, station.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}

	// ProcedureKey (used to resolve, before holding any record) must
	// equal storage_key's own derivation for a procedure_advertisement
	// (used to store) -- macula_record.erl computes both as SHA-256 of
	// the record's own procedure_uri payload field, independently; the
	// two are required to agree or a put would land somewhere a resolve
	// never looks.
	direct := ProcedureKey(uri)
	viaPayload, ok := textField(rec.Payload, "procedure_uri")
	if !ok || viaPayload != uri {
		t.Fatalf("payload procedure_uri = %q, ok=%v", viaPayload, ok)
	}
	viaStorage := ProcedureKey(viaPayload)
	if direct != viaStorage {
		t.Fatalf("ProcedureKey(uri) != ProcedureKey(payload's own procedure_uri)")
	}
}

func TestStationEndpointKeyIsDomainSeparatedFromBarePubkey(t *testing.T) {
	station := mustKeyPair(t)
	pub := station.NodeID()

	key := StationEndpointKey(pub)
	if len(key) != 32 {
		t.Fatalf("StationEndpointKey length = %d, want 32", len(key))
	}
	var barePubkey [32]byte
	copy(barePubkey[:], pub)
	if key == barePubkey {
		t.Fatalf("StationEndpointKey(pub) collides with the bare pubkey -- domain separation is broken")
	}
}

// TestReadStationEndpointHostAsByteString guards a real bug found live
// against the deployed fleet: macula_record.erl's with_host_list/2 puts
// each host in as a bare Erlang binary (CBOR byte string), never wrapped
// in {text, Bin} the way every other string field in that file is — so a
// naive AsText()-only read silently gets zero hosts back from a real,
// well-formed station_endpoint record. ReadStationEndpoint must accept
// byte-string list entries.
func TestReadStationEndpointHostAsByteString(t *testing.T) {
	station := mustKeyPair(t)
	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("quic_port"), Val: cbor.Uint64(4433)},
		{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{
			cbor.Bytes([]byte("2a01:4f8:c014:c8b3::be:01")), // byte string, NOT cbor.Text
		})},
	})
	rec := newEnvelope(TypeStationEndpoint, station.NodeID(), payload, time.Hour)

	ep, err := ReadStationEndpoint(rec)
	if err != nil {
		t.Fatalf("ReadStationEndpoint: %v", err)
	}
	if ep.QuicPort != 4433 {
		t.Errorf("QuicPort = %d, want 4433", ep.QuicPort)
	}
	if len(ep.HostAdvertised) != 1 || ep.HostAdvertised[0] != "2a01:4f8:c014:c8b3::be:01" {
		t.Fatalf("HostAdvertised = %v, want [\"2a01:4f8:c014:c8b3::be:01\"]", ep.HostAdvertised)
	}
}

func TestUUIDv7BitLayout(t *testing.T) {
	ms := int64(1_735_000_000_000) // arbitrary fixed timestamp
	v := uuidV7(ms)
	if len(v) != 16 {
		t.Fatalf("uuidV7 length = %d, want 16", len(v))
	}
	gotMs := int64(v[0])<<40 | int64(v[1])<<32 | int64(v[2])<<24 | int64(v[3])<<16 | int64(v[4])<<8 | int64(v[5])
	if gotMs != ms {
		t.Errorf("embedded timestamp = %d, want %d", gotMs, ms)
	}
	if version := v[6] >> 4; version != 0x7 {
		t.Errorf("version nibble = %x, want 7", version)
	}
	if variant := v[8] >> 6; variant != 0b10 {
		t.Errorf("variant bits = %b, want 10", variant)
	}
}

func TestDiscoveryURIMatchesRealmHexConvention(t *testing.T) {
	realm := make([]byte, 32) // all-zero DHT realm
	got := DiscoveryURI(realm, "hecate_mail.initiate_mailbox")
	want := strings.Repeat("0", 64) + "/hecate_mail.initiate_mailbox"
	if got != want {
		t.Fatalf("DiscoveryURI = %q, want %q", got, want)
	}
}
