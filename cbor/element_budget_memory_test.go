package cbor

import (
	"errors"
	"runtime"
	"testing"
)

// A chain of 64 maps, each declaring 1024 entries while holding one, is a few
// hundred bytes. Decoding refuses it, and allocates in proportion to the bytes
// present, not to the entries they declare.
func TestDecodeAllocatesInProportionToTheBytesPresentNotTheCountsDeclared(t *testing.T) {
	var input []byte
	for range MaxNestingDepth {
		input = append(input, 0xb9, 0x04, 0x00, 0x00) // a map declaring 1024 entries, then its first key, 0
	}
	input = append(input, 0x00) // the innermost value; every map then runs out of bytes

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := Decode(input)
	runtime.ReadMemStats(&after)

	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("Decode: %v, want ErrMalformed", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(512 * len(input)); allocated > limit {
		t.Fatalf("decoding %d bytes allocated %d bytes, want at most %d", len(input), allocated, limit)
	}
}
