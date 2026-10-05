package frame

import (
	"github.com/macula-io/macula-go/cbor"
)

// Handshake v5 (macula docs/design/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md section 3): the
// session proofs authenticate the neighbour once, so after HELLO no frame
// carries a neighbour signature, and QUIC's AEAD authenticates every frame. The
// liveness probe is liveness_ping, answered with liveness_pong and the same
// nonce by the peer's connection itself: unsigned, never handed on, and on a v5
// connection only.

const livenessNonceSize = 16

// VerifySessionFrame reads a received frame on a v5 connection: one that
// carries a neighbour signature is ErrMalformedFrame, and any other comes back
// as it is.
func VerifySessionFrame(frame cbor.Value) (cbor.Value, error) {
	entries, isMap := frame.AsMap()
	if !isMap {
		return cbor.Value{}, ErrMalformedFrame
	}
	if _, _, hasNeighbour := controlHeader(entries); hasNeighbour {
		return cbor.Value{}, ErrMalformedFrame
	}
	return frame, nil
}

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
	return cbor.Map(append(base(frameType, 0, freshFrameID(), currentMillis()), bytesEntry("nonce", nonce[:])))
}

// LivenessNonce reads a liveness frame: its type (liveness_ping or
// liveness_pong) and its nonce, or false for any other frame, or one whose
// nonce is not 16 bytes.
func LivenessNonce(frame cbor.Value) (frameType string, nonce [16]byte, ok bool) {
	entries, isMap := frame.AsMap()
	if !isMap {
		return "", nonce, false
	}
	frameType, _, _ = controlHeader(entries)
	value, isBytes := fieldOf(entries, "nonce").AsBytes()
	if (frameType != "liveness_ping" && frameType != "liveness_pong") || !isBytes || len(value) != livenessNonceSize {
		return "", nonce, false
	}
	copy(nonce[:], value)
	return frameType, nonce, true
}
