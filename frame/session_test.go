package frame

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// After HELLO the liveness probe is liveness_ping / liveness_pong, answered by
// the peer's connection, and read through its own table.

func TestLivenessFramesCarryTheirNonce(t *testing.T) {
	nonce := [16]byte{1, 2, 3}
	for _, c := range []struct {
		frameType string
		frame     cbor.Value
	}{{"liveness_ping", LivenessPingFrame(nonce)}, {"liveness_pong", LivenessPongFrame(nonce)}} {
		gotType, gotNonce, ok := LivenessNonce(c.frame)
		if !ok || gotType != c.frameType || gotNonce != nonce {
			t.Errorf("%s: (%q, %x, %t), want its type and nonce", c.frameType, gotType, gotNonce, ok)
		}
		wire, err := Encode(c.frame)
		if err != nil {
			t.Fatalf("%s: Encode: %v", c.frameType, err)
		}
		decoded, err := Decode(wire)
		if err != nil || !decoded.Complete {
			t.Fatalf("%s: Decode: %v", c.frameType, err)
		}
		if gotType, gotNonce, ok := LivenessNonce(decoded.Frame); !ok || gotType != c.frameType || gotNonce != nonce {
			t.Errorf("%s after the wire: (%q, %x, %t)", c.frameType, gotType, gotNonce, ok)
		}
	}
	short := cbor.Map(append(base("liveness_ping", freshFrameID(), currentMillis()), bytesEntry("nonce", []byte{1, 2})))
	if _, _, ok := LivenessNonce(short); ok {
		t.Error("a liveness_ping with a 2-byte nonce was read")
	}
	if _, _, ok := LivenessNonce(AdvertiseFrame([]byte("x"))); ok {
		t.Error("an ADVERTISE was read as a liveness frame")
	}
	neighbour := cbor.Map(append(base("liveness_ping", freshFrameID(), currentMillis()),
		bytesEntry("nonce", nonce[:]), valueEntry("neighbour", cbor.Map(nil))))
	if _, _, ok := LivenessNonce(neighbour); ok {
		t.Error("a liveness_ping carrying a neighbour signature was read")
	}
}
