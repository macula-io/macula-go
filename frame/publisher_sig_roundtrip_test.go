package frame

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// Full encode->decode round trip with BOTH publisher_sig and the
// per-hop signature present, mirroring exactly what
// connection.Session.Publish now builds. Catches any structural
// corruption from attaching two fields in sequence that a
// signature-only unit test (publisher_sig_vector_test.go) wouldn't.
func TestPublishFrameWithBothSignaturesRoundTrips(t *testing.T) {
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	realm := make([]byte, 32)
	spec := NewPublishSpec("acme/svc.do", realm, id.NodeID(), 1,
		cbor.Bytes([]byte("hello")), 1_700_000_000_000)

	unsigned := Publish(spec)
	withPubSig := SignPublisher(unsigned, id)
	fullySigned := Sign(withPubSig, id)

	encoded, err := Encode(fullySigned)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	t.Logf("encoded length: %d", len(encoded))

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !decoded.Complete {
		t.Fatal("Decode: incomplete, expected a full frame")
	}
	if decoded.Consumed != len(encoded) {
		t.Errorf("Decode consumed %d, want %d", decoded.Consumed, len(encoded))
	}

	if err := Verify(decoded.Frame, id.NodeID()); err != nil {
		t.Errorf("per-hop Verify on decoded frame: %v", err)
	}
	if err := VerifyPublisher(decoded.Frame); err != nil {
		t.Errorf("VerifyPublisher on decoded frame: %v", err)
	}

	// Both fields must actually be present post-round-trip.
	if _, ok := decoded.Frame.Get("publisher_sig"); !ok {
		t.Error("decoded frame lost publisher_sig")
	}
	if _, ok := decoded.Frame.Get("signature"); !ok {
		t.Error("decoded frame lost signature")
	}
}
