package frame

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
)

// Handshake v5 (macula docs/design/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md section 3): after HELLO no frame carries a
// neighbour signature, and the liveness probe is liveness_ping / liveness_pong, answered by the peer's connection.

func TestAV5ConnectionReadsFramesWithoutANeighbourSignatureAndRefusesOneThatHasIt(t *testing.T) {
	ping := LivenessPingFrame([16]byte{7})
	if got, err := VerifySessionFrame(ping); err != nil || !bytes.Equal(cbor.Encode(got), cbor.Encode(ping)) {
		t.Errorf("an unsigned frame on v5: (%v, %v), want it as it is", got, err)
	}
	goodbye, err := GoodbyeFrame("bye", nil)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := goodbye.AsMap()
	signed := cbor.Map(append(entries, valueEntry("neighbour", cbor.Map(nil))))
	if _, err := VerifySessionFrame(signed); !errors.Is(err, ErrMalformedFrame) {
		t.Errorf("a neighbour-signed frame on v5: %v, want ErrMalformedFrame", err)
	}
}

func TestLivenessFramesCarryTheirNonceAndAreNeverNeighbourSigned(t *testing.T) {
	nonce := [16]byte{1, 2, 3}
	for _, c := range []struct {
		frameType string
		frame     cbor.Value
	}{{"liveness_ping", LivenessPingFrame(nonce)}, {"liveness_pong", LivenessPongFrame(nonce)}} {
		gotType, gotNonce, ok := LivenessNonce(c.frame)
		if !ok || gotType != c.frameType || gotNonce != nonce {
			t.Errorf("%s: (%q, %x, %t), want its type and nonce", c.frameType, gotType, gotNonce, ok)
		}
		if NeighbourSigned(profile.PQHybrid, c.frameType) {
			t.Errorf("%s is neighbour-signed in pq_hybrid; it exists only on v5", c.frameType)
		}
		wire, err := Encode(c.frame)
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.frameType, err)
		}
		decoded := decodedWhole(t, wire)
		if gotType, gotNonce, ok := LivenessNonce(decoded); !ok || gotType != c.frameType || gotNonce != nonce {
			t.Errorf("%s after the wire: (%q, %x, %t)", c.frameType, gotType, gotNonce, ok)
		}
	}
	short := cbor.Map(append(base("liveness_ping", 0, freshFrameID(), currentMillis()), bytesEntry("nonce", []byte{1, 2})))
	if _, _, ok := LivenessNonce(short); ok {
		t.Error("a liveness_ping with a 2-byte nonce was read")
	}
	if _, _, ok := LivenessNonce(AdvertiseFrame([]byte("x"))); ok {
		t.Error("an ADVERTISE was read as a liveness frame")
	}
}
