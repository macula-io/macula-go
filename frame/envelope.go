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

// ProtocolVersion is the version field every frame carries.
const ProtocolVersion = 2

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

// base builds the envelope every frame carries, matching macula_frame's
// base/2. Field order doesn't matter — canonical CBOR re-sorts by
// encoded key bytes at encode time regardless (see package cbor).
func base(frameType string, capabilities uint64, frameID []byte, sentAtMs int64) []cbor.MapEntry {
	return []cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(ProtocolVersion)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text(frameType)},
		{Key: cbor.Text("frame_id"), Val: cbor.Bytes(frameID)},
		{Key: cbor.Text("sent_at_ms"), Val: cbor.Int(sentAtMs)},
		{Key: cbor.Text("capabilities"), Val: cbor.Uint64(capabilities)},
		{Key: cbor.Text("realm"), Val: cbor.Null()},
		{Key: cbor.Text("call_id"), Val: cbor.Null()},
		{Key: cbor.Text("source_route"), Val: cbor.Null()},
	}
}

// withField replaces fields' existing entry for key (if any) or appends
// a new one. MUST be used instead of a raw append whenever overriding a
// base() sentinel field (realm, call_id, source_route) — cbor.Map is a
// plain slice of pairs with none of a real map's key-uniqueness, so a
// raw append on top of base()'s Null entry would silently produce a
// wire frame with two entries under the same key instead of one
// overridden value. Caught for real during the Rust port's own
// differential-vector work; fixed here from the start rather than
// rediscovered.
func withField(fields []cbor.MapEntry, key string, val cbor.Value) []cbor.MapEntry {
	for i := range fields {
		if t, ok := fields[i].Key.AsText(); ok && t == key {
			fields[i].Val = val
			return fields
		}
	}
	return append(fields, cbor.MapEntry{Key: cbor.Text(key), Val: val})
}
