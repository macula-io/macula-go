// Package frame implements macula 12's frames: the requests, replies, relay
// errors, publications and stream frames that carry signed objects
// (MACULA-PQ-REQUEST-V1 and its kin, see signed_frames.go), the control frames
// a pq_hybrid link neighbour-signs, the decoding rule's payload bounds, and the
// length-prefixed wire codec. Ported from macula's src/peering/macula_frame.erl.
//
// A wire frame is `<Length:4 bytes big-endian><Cbor>` where Cbor is the
// deterministic encoding (package cbor) of a single map with version and
// frame_type. No frame carries a frame-level signature: what is signed is the
// signed object a frame holds, and, in pq_hybrid, a control frame's neighbour
// signature.
package frame

import (
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
)

// WireVersion is the wire this library speaks, major.minor: the frozen core of
// macula docs/design/WIRE_1_0.md, which every wire 1.x peer shares.
const WireVersion = "1.0"

// ProtocolVersion is the version every frame carries: wire 1.0 binds the frame
// version to the handshake version, 5 (macula docs/design/WIRE_1_0.md section 2).
const ProtocolVersion = 5

// MaxFrameBytes is the CBOR payload size cap — matches ?MAX_FRAME_BYTES
// (16#FFFFFF) exactly: 16 MiB minus one byte.
const MaxFrameBytes = 0x00FF_FFFF

func currentMillis() int64 {
	return time.Now().UnixMilli()
}

func freshFrameID() []byte {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if crypto/rand is broken system-wide — nothing
		// a caller could meaningfully recover from either.
		panic("frame: uuid.NewV7: " + err.Error())
	}
	b := id
	return b[:]
}

// base builds the envelope every frame carries: version, frame_type, frame_id
// and sent_at_ms. The other envelope keys (realm, call_id, source_route, ext)
// are added only by a frame that has a value for them, never sent as null, so
// one frame has one encoding. Field order doesn't matter: canonical CBOR
// re-sorts by encoded key bytes at encode time (see package cbor).
func base(frameType string, frameID []byte, sentAtMs int64) []cbor.MapEntry {
	return []cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(ProtocolVersion)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text(frameType)},
		{Key: cbor.Text("frame_id"), Val: cbor.Bytes(frameID)},
		{Key: cbor.Text("sent_at_ms"), Val: cbor.Int(sentAtMs)},
	}
}
