package frame

import (
	"errors"
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
	// ExtRefused is wire_ext_refused, by extension name: unknown critical
	// extensions on unsigned frames the receiver dropped (CountExtRefused).
	ExtRefused map[string]uint64
	// EnumFallback is wire_enum_fallback, by field name: per-hop enum values
	// the receiver does not know, read as the field's fallback.
	EnumFallback map[string]uint64
}

var wireCounters = struct {
	sync.Mutex
	unknownFrameType uint64
	extIgnored       map[string]uint64
	extRefused       map[string]uint64
	enumFallback     map[string]uint64
}{extIgnored: map[string]uint64{}, extRefused: map[string]uint64{}, enumFallback: map[string]uint64{}}

// maxCountedNames is how many extension names each extension counter keeps;
// further names count under other (WIRE_1_0.md section 8), so a peer cannot
// grow them without bound.
const maxCountedNames = 64

// countNamed counts one under name in counts, or under other once counts
// holds maxCountedNames names besides it. The caller holds wireCounters.
func countNamed(counts map[string]uint64, name string) {
	names := len(counts)
	if _, hasOther := counts["other"]; hasOther {
		names--
	}
	if _, has := counts[name]; !has && names >= maxCountedNames {
		name = "other"
	}
	counts[name]++
}

// WireCounters is a snapshot of this process's wire counters.
func WireCounters() WireCounts {
	wireCounters.Lock()
	defer wireCounters.Unlock()
	return WireCounts{
		UnknownFrameType: wireCounters.unknownFrameType,
		ExtIgnored:       maps.Clone(wireCounters.extIgnored),
		ExtRefused:       maps.Clone(wireCounters.extRefused),
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
	countNamed(wireCounters.extIgnored, name)
	wireCounters.Unlock()
}

// CountExtRefused counts wire_ext_refused once per unknown critical extension
// name err names, for an unsigned frame dropped for them; any other error
// counts nothing.
func CountExtRefused(err error) {
	var unsupported *ExtensionUnsupportedError
	if !errors.As(err, &unsupported) {
		return
	}
	wireCounters.Lock()
	for _, name := range unsupported.Names {
		countNamed(wireCounters.extRefused, name)
	}
	wireCounters.Unlock()
}

// countEnumFallback counts one per-hop enum value read as its field's fallback.
func countEnumFallback(field string) {
	wireCounters.Lock()
	wireCounters.enumFallback[field]++
	wireCounters.Unlock()
}
