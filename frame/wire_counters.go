package frame

import (
	"maps"
	"sync"
)

// The wire 1.0 counters (macula docs/design/WIRE_1_0.md section 8), one set per
// process: what a receiver read past instead of refusing.

// WireCounts is a snapshot of the wire counters.
type WireCounts struct {
	// UnknownFrameType is wire_unknown_frame_type: frames of a type the
	// receiver does not know, dropped with the link left up.
	UnknownFrameType uint64
	// ExtIgnored is wire_ext_ignored, by extension name: non-critical
	// extensions the receiver does not know.
	ExtIgnored map[string]uint64
	// EnumFallback is wire_enum_fallback, by field name: per-hop enum values
	// the receiver does not know, read as the field's fallback.
	EnumFallback map[string]uint64
}

var wireCounters = struct {
	sync.Mutex
	unknownFrameType uint64
	extIgnored       map[string]uint64
	enumFallback     map[string]uint64
}{extIgnored: map[string]uint64{}, enumFallback: map[string]uint64{}}

// WireCounters is a snapshot of this process's wire counters.
func WireCounters() WireCounts {
	wireCounters.Lock()
	defer wireCounters.Unlock()
	return WireCounts{
		UnknownFrameType: wireCounters.unknownFrameType,
		ExtIgnored:       maps.Clone(wireCounters.extIgnored),
		EnumFallback:     maps.Clone(wireCounters.enumFallback),
	}
}

// CountUnknownFrameType counts one dropped frame of a type the receiver does
// not know.
func CountUnknownFrameType() {
	wireCounters.Lock()
	wireCounters.unknownFrameType++
	wireCounters.Unlock()
}

// countExtIgnored counts one ignored extension under its name, which the
// envelope rule already bounds to 64 bytes.
func countExtIgnored(name string) {
	wireCounters.Lock()
	wireCounters.extIgnored[name]++
	wireCounters.Unlock()
}

// countEnumFallback counts one per-hop enum value read as its field's fallback.
func countEnumFallback(field string) {
	wireCounters.Lock()
	wireCounters.enumFallback[field]++
	wireCounters.Unlock()
}
