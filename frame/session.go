package frame

import (
	"github.com/macula-io/macula-go/cbor"
)

// After HELLO the liveness probe is liveness_ping, answered with liveness_pong
// and the same nonce by the peer's connection itself: unsigned, and never
// handed on (macula docs/design/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md section 3).

const livenessNonceSize = 16

// LivenessPingFrame is macula 13.2.0's liveness_ping with a 16-byte nonce.
func LivenessPingFrame(nonce [16]byte) cbor.Value {
	return livenessFrame("liveness_ping", nonce)
}

// LivenessPongFrame is macula 13.2.0's liveness_pong, answering the
// liveness_ping of the same nonce.
func LivenessPongFrame(nonce [16]byte) cbor.Value {
	return livenessFrame("liveness_pong", nonce)
}

func livenessFrame(frameType string, nonce [16]byte) cbor.Value {
	return cbor.Map(append(base(frameType, freshFrameID(), currentMillis()), bytesEntry("nonce", nonce[:])))
}

// livenessTable is a liveness frame's fields: the envelope it may carry and
// its 16-byte nonce, nothing else (WIRE_1_0.md section 3.1).
var livenessTable = map[string]fieldRule{
	"version":    protocolVersion,
	"frame_type": textIn("liveness_ping", "liveness_pong"),
	"frame_id":   bytesOf(16),
	"sent_at_ms": protocolUint,
	"nonce":      bytesOf(livenessNonceSize),
}

// LivenessNonce reads a liveness frame, ext already read past: its type
// (liveness_ping or liveness_pong) and its nonce, or false for any other
// frame, or one with a field its table does not have or without its nonce.
func LivenessNonce(frame cbor.Value) (frameType string, nonce [16]byte, ok bool) {
	fields, read := readFields(frame, livenessTable)
	if !read || !hasFields(fields, "version", "frame_type", "nonce") {
		return "", nonce, false
	}
	frameType, _ = fields["frame_type"].AsText()
	value, _ := fields["nonce"].AsBytes()
	copy(nonce[:], value)
	return frameType, nonce, true
}
