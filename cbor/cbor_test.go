package cbor

import (
	"bytes"
	"testing"
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
