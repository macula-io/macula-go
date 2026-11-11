package cbor

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/internal/wire10vectors"
)

// The fuzzers hold the wire parsers to one invariant (macula-go#39): every
// byte string either decodes to a value that re-encodes canonically, or is
// refused with one of the package's own errors — never a panic, and never a
// value that outgrows its input. The seed corpus is every entry of the shared
// decoding-rule vectors (testdata/decoding_rule_v1.json), whose 59 cases are the
// decoder's edges, together with every frame body and record object of the wire
// 1.0 vectors; both are read from their files, so a regenerated vector set
// reseeds the fuzzers instead of leaving a copy behind here.
//
// A hang is a package test timeout: the decoder bounds its own work (depth,
// elements, the bytes it needs before it allocates), so nothing here waits on
// anything but the input.

// decodeRefusals are every error Decode documents. A refusal outside this list
// is an error a caller cannot tell from a bug, so it fails the fuzzer by name.
var decodeRefusals = []error{
	ErrMalformed,
	ErrTrailingBytes,
	ErrBadKey,
	ErrDuplicateKey,
	ErrInvalidText,
	ErrNestingTooDeep,
	ErrIntegerOutOfRange,
	ErrTooManyElements,
}

func refusedAsOneOf(t *testing.T, err error, refusals []error) {
	t.Helper()
	for _, refusal := range refusals {
		if errors.Is(err, refusal) {
			return
		}
	}
	t.Fatalf("refused with an error that is not one of the package's: %v", err)
}

// The most bytes Encode writes per byte of input, plus a little slack: the
// smallest item a peer can send is a one-byte head, and the widest one this
// package writes is a double-precision float (nine bytes) for a half-precision
// float's three. A decoded value that encodes past this outgrew its input.
const (
	maxEncodedPerInputByte = 32
	encodeSlack            = 32
)

// FuzzDecode holds Decode to the invariant on any byte string: a value whose
// encoding is canonical, or a typed refusal.
func FuzzDecode(f *testing.F) {
	seedDecodingRule(f)
	seedWireBodies(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			refusedAsOneOf(t, err, decodeRefusals)
			return
		}
		checkReEncodes(t, data, v)
	})
}

// seedDecodingRule adds every entry of the shared decoding-rule vectors. An
// entry read as a request's fields rather than under the rule alone is frame's
// to run (frame's TestRequestFieldVectors), and is passed over as
// TestDecodingRuleVectors passes it over.
func seedDecodingRule(f *testing.F) {
	vectors := readDecodingRuleVectors(f)
	for _, e := range vectors.Entries {
		if e.Via != "" && e.Via != "record" {
			continue
		}
		input, err := hex.DecodeString(e.CBOR)
		if err != nil {
			f.Fatalf("%s: hex %q: %v", e.Name, e.CBOR, err)
		}
		f.Add(input)
	}
}

// seedWireBodies adds every frame body and record object of the wire 1.0
// vectors.
func seedWireBodies(f *testing.F) {
	for _, body := range []struct{ class, field string }{
		{"frames", "frame"},
		{"envelope", "frame"},
		{"verify", "object"},
		{"custodian", "object"},
	} {
		seeds, err := wire10vectors.HexInputs(body.class, body.field)
		if err != nil {
			f.Fatalf("%s: %v", body.class, err)
		}
		for _, seed := range seeds {
			f.Add(seed)
		}
	}
}

// checkReEncodes holds a decoded value to the wire Encode would send: the same
// bytes whatever order its map entries arrived in, in canonical key order, and
// no larger than its input.
func checkReEncodes(t *testing.T, data []byte, v Value) {
	t.Helper()
	encoded := Encode(v)
	// Decode keeps a map's keys in the order they arrived and the rule accepts
	// any order, so the encoding is what is held to canonical form: reversing
	// every map's entries may not change a byte, and the bytes it writes must
	// read back with every map in canonical order.
	if reversed := Encode(reverseMaps(v)); !bytes.Equal(encoded, reversed) {
		t.Fatalf("Encode depends on the order a map's entries arrived in: %x, then %x", encoded, reversed)
	}
	back, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Encode's own bytes do not decode: %v (%x)", err, encoded)
	}
	if err := Canonical(back); err != nil {
		t.Fatalf("an encoding that is not canonical: %v (%x)", err, encoded)
	}
	if second := Encode(back); !bytes.Equal(encoded, second) {
		t.Fatalf("re-encoding is not deterministic: %x, then %x", encoded, second)
	}
	if len(encoded) > maxEncodedPerInputByte*len(data)+encodeSlack {
		t.Fatalf("%d input bytes decode to %d encoded bytes", len(data), len(encoded))
	}
}

// reverseMaps is v with every map's entries in the reverse order, recursively:
// what Encode must not depend on.
func reverseMaps(v Value) Value {
	switch v.Kind() {
	case KindMap:
		entries, _ := v.AsMap()
		out := make([]MapEntry, len(entries))
		for i, e := range entries {
			out[len(entries)-1-i] = MapEntry{Key: reverseMaps(e.Key), Val: reverseMaps(e.Val)}
		}
		return Value{kind: KindMap, mapV: out}
	case KindList:
		items, _ := v.AsList()
		out := make([]Value, len(items))
		for i, item := range items {
			out[i] = reverseMaps(item)
		}
		return Value{kind: KindList, listV: out}
	}
	return v
}
