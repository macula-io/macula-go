package connection

import (
	"fmt"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// An oversize frame_type the control stream doesn't carry is counted under
// "unknown": nothing the peer chose becomes a count key.
func TestAnOversizeFrameTypeIsCountedAsUnknown(t *testing.T) {
	s, fc, id := readingSession(t)
	fc.send(t, bareFrame(strings.Repeat("x", 100_000)))
	roundTrip(t, s, fc, id)

	counts := s.Unrouted()
	if counts["unknown"] != 1 || len(counts) != 1 {
		t.Fatalf("Unrouted() has %d keys %q, want only unknown 1", len(counts), keysOf(counts))
	}
}

// Many distinct frame types no macula frame defines, and a frame_type that is
// missing, not text or empty, leave the counts holding only defined names and
// "unknown".
func TestManyDistinctUnknownFrameTypesLeaveOnlyDefinedNamesAndUnknown(t *testing.T) {
	s, fc, id := readingSession(t)
	for i := range 1000 {
		fc.send(t, bareFrame(fmt.Sprintf("not_a_frame_type_%d", i)))
	}
	fc.send(t, bareFrame("stream_data"))
	fc.send(t, withoutField(bareFrame("stream_data"), "frame_type"))
	fc.send(t, withField(bareFrame("stream_data"), "frame_type", cbor.Bytes([]byte("stream_data"))))
	fc.send(t, bareFrame(""))
	roundTrip(t, s, fc, id)

	counts := s.Unrouted()
	if counts["unknown"] != 1003 || counts["stream_data"] != 1 || len(counts) != 2 {
		t.Fatalf("Unrouted() has %d keys %q with unknown %d and stream_data %d, want only unknown 1003 and stream_data 1",
			len(counts), keysOf(counts), counts["unknown"], counts["stream_data"])
	}
}

// keysOf is up to ten of counts' keys, each cut to 40 bytes, for a readable
// failure.
func keysOf(counts map[string]uint64) []string {
	keys := make([]string, 0, 10)
	for k := range counts {
		keys = append(keys, k[:min(len(k), 40)])
		if len(keys) == 10 {
			break
		}
	}
	return keys
}
