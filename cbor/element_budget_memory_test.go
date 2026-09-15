package cbor

import (
	"errors"
	"runtime"
	"testing"
)

// A chain of 64 maps, each declaring 1024 entries while holding one, is a few
// hundred bytes. Decoding refuses it, and allocates in proportion to the bytes
// present, not to the entries they declare.
//
// The allocation counter covers the whole process, so the measurement runs on
// one P and keeps the smallest of several runs: anything else allocating can
// only add to a run, never take from it.
func TestDecodeAllocatesInProportionToTheBytesPresentNotTheCountsDeclared(t *testing.T) {
	var input []byte
	for range MaxNestingDepth {
		input = append(input, 0xb9, 0x04, 0x00, 0x00) // a map declaring 1024 entries, then its first key, 0
	}
	input = append(input, 0x00) // the innermost value; every map then runs out of bytes

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	smallest := ^uint64(0)
	for range 5 {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		_, err := Decode(input)
		runtime.ReadMemStats(&after)
		if !errors.Is(err, ErrMalformed) {
			t.Fatalf("Decode: %v, want ErrMalformed", err)
		}
		smallest = min(smallest, after.TotalAlloc-before.TotalAlloc)
	}
	if limit := uint64(512 * len(input)); smallest > limit {
		t.Fatalf("decoding %d bytes allocated %d bytes, want at most %d", len(input), smallest, limit)
	}
}
