package cbor

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestEncodeMinimalLengthBoundaries(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want []byte
	}{
		{"uint 0", Uint64(0), []byte{0x00}},
		{"uint 23 (last inline)", Uint64(23), []byte{0x17}},
		{"uint 24 (first 1-byte)", Uint64(24), []byte{0x18, 0x18}},
		{"uint 255 (last 1-byte)", Uint64(255), []byte{0x18, 0xFF}},
		{"uint 256 (first 2-byte)", Uint64(256), []byte{0x19, 0x01, 0x00}},
		{"uint 65535 (last 2-byte)", Uint64(65535), []byte{0x19, 0xFF, 0xFF}},
		{"uint 65536 (first 4-byte)", Uint64(65536), []byte{0x1A, 0x00, 0x01, 0x00, 0x00}},
		{"uint 4294967296 (first 8-byte)", Uint64(4294967296),
			[]byte{0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}},
		{"negint -1 (magnitude 0)", Int(-1), []byte{0x20}},
		{"negint -24 (magnitude 23, last inline)", Int(-24), []byte{0x37}},
		{"negint -25 (magnitude 24, first 1-byte)", Int(-25), []byte{0x38, 0x18}},
		{"bytes", Bytes([]byte{1, 2, 3}), []byte{0x43, 0x01, 0x02, 0x03}},
		{"text empty", Text(""), []byte{0x60}},
		{"text a", Text("a"), []byte{0x61, 0x61}},
		{"list [1,2,3]", List([]Value{Int(1), Int(2), Int(3)}), []byte{0x83, 0x01, 0x02, 0x03}},
		{"null", Null(), []byte{0xF6}},
		{"float 1.0 (always binary64)", Float(1.0),
			[]byte{0xFB, 0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
		// A value that would round-trip in float32 (e.g. 2.5) must STILL
		// encode as binary64 — the deliberate divergence from RFC 8949's
		// shortest-width canonical rule (§4).
		{"float 2.5 stays binary64", Float(2.5),
			[]byte{0xFB, 0x40, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Encode(c.v)
			if !bytes.Equal(got, c.want) {
				t.Errorf("Encode(%s) = % X, want % X", c.name, got, c.want)
			}
		})
	}
}

func TestMapKeysSortByEncodedBytesNotInsertionOrder(t *testing.T) {
	// {"b": 1, "a": 2} -- "a" (0x61 0x61) sorts before "b" (0x61 0x62)
	// regardless of insertion order.
	v := Map([]MapEntry{
		{Key: Text("b"), Val: Int(1)},
		{Key: Text("a"), Val: Int(2)},
	})
	got := Encode(v)
	want := []byte{
		0xA2,             // map(2)
		0x61, 0x61, 0x02, // "a": 2
		0x61, 0x62, 0x01, // "b": 1
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Encode(map) = % X, want % X", got, want)
	}
}

func TestMapKeySortIsByEncodedBytesAcrossMajorTypes(t *testing.T) {
	// A key that's a 1-byte-encoded int (0x00) sorts before a key that's
	// a text string starting with a higher first byte, purely by their
	// own encoded bytes -- this is the case a naive "sort by original
	// representation" implementation gets wrong (§4's own warning).
	v := Map([]MapEntry{
		{Key: Text("x"), Val: Int(1)}, // encodes to 0x61 0x78
		{Key: Int(0), Val: Int(2)},    // encodes to 0x00
	})
	got := Encode(v)
	want := []byte{
		0xA2,
		0x00, 0x02, // key 0x00 sorts first
		0x61, 0x78, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Encode(mixed-key map) = % X, want % X", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	original := Map([]MapEntry{
		{Key: Text("frame_type"), Val: Text("connect")},
		{Key: Text("version"), Val: Int(2)},
		{Key: Text("node_id"), Val: Bytes(bytes.Repeat([]byte{0xAB}, 32))},
		{Key: Text("capabilities"), Val: Uint64(0)},
		{Key: Text("realms"), Val: List([]Value{})},
		{Key: Text("addresses"), Val: Null()},
		{Key: Text("weight"), Val: Float(-3.5)},
	})
	encoded := Encode(original)

	decoded, consumed, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if consumed != len(encoded) {
		t.Fatalf("Decode consumed %d bytes, want %d", consumed, len(encoded))
	}

	// Re-encoding the decoded value must reproduce the exact same bytes --
	// the actual property that matters for signature verification.
	reEncoded := Encode(decoded)
	if !bytes.Equal(reEncoded, encoded) {
		t.Errorf("re-encode after decode diverged:\n got % X\nwant % X", reEncoded, encoded)
	}

	ft, ok := decoded.Get("frame_type")
	if !ok {
		t.Fatal("frame_type missing after decode")
	}
	if s, _ := ft.AsText(); s != "connect" {
		t.Errorf("frame_type = %q, want \"connect\"", s)
	}
}

func TestDecodeRejectsTags(t *testing.T) {
	// Major type 6 (tags) — not supported at all, per §4.
	_, _, err := Decode([]byte{0xC0, 0x00}) // tag 0, then a 0
	if err == nil {
		t.Fatal("Decode: expected an error for major type 6 (tags), got none")
	}
}

func TestDecodeRejectsBooleans(t *testing.T) {
	// Major 7, AI 21 (true) — not supported; only null + 3 float widths.
	_, _, err := Decode([]byte{0xF5})
	if err == nil {
		t.Fatal("Decode: expected an error for a CBOR boolean, got none")
	}
}

func TestDecodeAcceptsFloat16AndFloat32ForInterop(t *testing.T) {
	// float16: 1.0 = 0x3C00
	v, n, err := Decode([]byte{0xF9, 0x3C, 0x00})
	if err != nil {
		t.Fatalf("Decode float16: %v", err)
	}
	if n != 3 {
		t.Errorf("consumed %d, want 3", n)
	}
	f, _ := v.AsFloat()
	if f != 1.0 {
		t.Errorf("float16(1.0) decoded as %v", f)
	}

	// float32: 1.0 = 0x3F800000
	v, n, err = Decode([]byte{0xFA, 0x3F, 0x80, 0x00, 0x00})
	if err != nil {
		t.Fatalf("Decode float32: %v", err)
	}
	if n != 5 {
		t.Errorf("consumed %d, want 5", n)
	}
	f, _ = v.AsFloat()
	if f != 1.0 {
		t.Errorf("float32(1.0) decoded as %v", f)
	}
}

func TestDuplicateMapKeysLastWriteWins(t *testing.T) {
	// {"a": 1, "a": 2} on the wire, hand-built since Encode never emits
	// duplicates itself -- decode must still handle a peer that does.
	raw := []byte{
		0xA2,
		0x61, 0x61, 0x01, // "a": 1
		0x61, 0x61, 0x02, // "a": 2 (should win)
	}
	v, _, err := Decode(raw)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	got, ok := v.Get("a")
	if !ok {
		t.Fatal("key \"a\" missing")
	}
	n, _ := got.AsInt64()
	if n != 2 {
		t.Errorf("duplicate key: got %d, want 2 (last write)", n)
	}
}

// TestDecodeMapDedupIsNotQuadratic guards against a regression to the
// pre-2026-09-05 linear-scan dedup in decodeOne's majorMap case, which
// made decoding O(n^2) in the key count -- a pre-auth algorithmic-
// complexity DoS (reachable during frame decode, before any signature
// check). Measured before the fix: 16,000 distinct keys took ~6.5s and
// scaling was clearly quadratic (each doubling of n roughly quadrupled
// the time); after the fix, the same input decodes in single-digit
// milliseconds. This budget is generous on purpose -- it only needs to
// catch a return to O(n^2), not enforce a specific constant factor.
func TestDecodeMapDedupIsNotQuadratic(t *testing.T) {
	const n = 20000
	entries := make([]MapEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, MapEntry{Key: Uint64(uint64(i)), Val: Uint64(uint64(i))})
	}
	wire := Encode(Map(entries))

	start := time.Now()
	v, _, err := Decode(wire)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("decoding a %d-key map took %v -- looks quadratic again (O(n) should take single-digit ms)", n, elapsed)
	}
	if len(v.mapV) != n {
		t.Fatalf("decoded map has %d entries, want %d", len(v.mapV), n)
	}
	last, _ := v.mapV[n-1].Val.AsInt64()
	if last != int64(n-1) {
		t.Errorf("decoded value for last key: got %d, want %d", last, n-1)
	}
}

// TestDecodeRejectsHugeClaimedCountWithoutPanicking guards against a
// process-killing DoS found while reviewing the fix above: `count` comes
// straight off the wire via readAIValue and is never checked against how
// many bytes actually follow, so a 9-byte frame can claim a map or list
// of 2^64-1 entries. Before preallocCap, `make([]MapEntry, 0, count)`
// (and the sibling majorList/indexOfKey allocations) took that count
// directly as a capacity hint, which panics with "makeslice: cap out of
// range" -- and nothing between here and the connection goroutine
// (RecvFrame -> frame.Decode -> cbor.Decode) recovers, so a single
// malformed frame killed the whole process. Decode must return an error,
// never panic, on attacker-controlled input.
func TestDecodeRejectsHugeClaimedCountWithoutPanicking(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		// major 5 (map, head 0xA0), ai=27 (0x1B): next 8 bytes are the
		// full uint64 count. 0xFFFFFFFFFFFFFFFF entries claimed, 0 bytes
		// of actual key/value data follow.
		{"map claims 2^64-1 entries", []byte{0xBB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
		// major 4 (list, head 0x80) with the same ai/length shape.
		{"list claims 2^64-1 entries", []byte{0x9B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Decode panicked on attacker-controlled input: %v", r)
				}
			}()
			_, _, err := Decode(tc.raw)
			if err == nil {
				t.Fatal("expected a decode error for an under-filled huge-count frame, got nil")
			}
		})
	}
}

// nestedListPayload is depth one-element lists around a uint 0, one byte
// per level.
func nestedListPayload(depth int) []byte {
	return append(bytes.Repeat([]byte{0x81}, depth), 0x00)
}

func TestDecodeAcceptsNestingAtTheDepthLimit(t *testing.T) {
	if _, _, err := Decode(nestedListPayload(MaxNestingDepth)); err != nil {
		t.Fatalf("Decode at %d levels: %v, want it decoded", MaxNestingDepth, err)
	}
}

func TestDecodeRejectsNestingOnePastTheDepthLimit(t *testing.T) {
	if _, _, err := Decode(nestedListPayload(MaxNestingDepth + 1)); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("Decode at %d levels: %v, want ErrNestingTooDeep", MaxNestingDepth+1, err)
	}
}

// A million levels is a 1 MB frame, well under the frame cap. A test process
// that dies here instead of passing or failing means the cap has regressed.
func TestDecodeRejectsExtremeNestingWithoutCrashing(t *testing.T) {
	if _, _, err := Decode(nestedListPayload(1_000_000)); !errors.Is(err, ErrNestingTooDeep) {
		t.Fatalf("Decode at a million levels: %v, want ErrNestingTooDeep", err)
	}
}

// Duplicate map keys merge exactly when their canonical encodings are
// equal: the wire order of a nested map, a non-minimal head and a nested
// map's own duplicates don't make keys differ, while element order, kind
// and type do.
func TestDecodeMergesDuplicateKeysExactlyWhenTheirEncodingsAreEqual(t *testing.T) {
	cases := []struct {
		name    string
		hex     string
		entries int
	}{
		{"maps with the same entries in another wire order", "A2A2616101616202 01 A2616202616101 02", 1},
		{"a map whose own duplicate leaves it equal to another", "A2A2616101616102 01 A1616102 02", 1},
		{"the same uint with a non-minimal head", "A2 1801 01 01 02", 1},
		{"lists with their elements in another order", "A2 820102 01 820201 02", 2},
		{"a uint and the equal float", "A2 01 01 FB3FF0000000000000 02", 2},
		{"bytes and text with the same content", "A2 4161 01 6161 02", 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustHex(t, tc.hex)
			v, n, err := Decode(raw)
			if err != nil || n != len(raw) {
				t.Fatalf("Decode: consumed %d of %d, err %v", n, len(raw), err)
			}
			entries, ok := v.AsMap()
			if !ok || len(entries) != tc.entries {
				t.Fatalf("decoded %d entries, want %d", len(entries), tc.entries)
			}
			if last, _ := entries[len(entries)-1].Val.AsInt64(); last != 2 {
				t.Fatalf("the last entry's value is %d, want the later write, 2", last)
			}
		})
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

// A chain of MaxNestingDepth one-entry maps, each keyed by the next, around
// a 512 KiB byte-string key: each key's identity is worked out once while it
// decodes, not again at every level above it, so decoding allocates in
// proportion to the input rather than to its depth squared.
func TestDecodeMapWithALargeDeeplyNestedKeyIsNotQuadraticInDepth(t *testing.T) {
	const blobLen = 512 * 1024
	raw := bytes.Repeat([]byte{0xA1}, MaxNestingDepth)
	raw = append(raw, 0x5A)
	raw = binary.BigEndian.AppendUint32(raw, blobLen)
	raw = append(raw, bytes.Repeat([]byte{0x41}, blobLen)...)
	raw = append(raw, bytes.Repeat([]byte{0x00}, MaxNestingDepth)...)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	v, n, err := Decode(raw)
	runtime.ReadMemStats(&after)
	if err != nil || n != len(raw) {
		t.Fatalf("Decode: consumed %d of %d, err %v", n, len(raw), err)
	}
	for level := 0; level < MaxNestingDepth; level++ {
		entries, ok := v.AsMap()
		if !ok || len(entries) != 1 {
			t.Fatalf("level %d is not a one-entry map", level)
		}
		v = entries[0].Key
	}
	if blob, ok := v.AsBytes(); !ok || len(blob) != blobLen {
		t.Fatalf("the innermost key is not the %d-byte string", blobLen)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 8*uint64(len(raw)) {
		t.Fatalf("decoding %d bytes allocated %d MiB, want at most 8 times the input", len(raw), allocated>>20)
	}
}
