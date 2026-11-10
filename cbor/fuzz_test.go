package cbor

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/internal/wire10vectors"
)

// The fuzzers hold the wire parsers to one invariant (macula-go#39): every
// byte string either decodes to a value that re-encodes deterministically, or
// is refused with one of the package's own errors — never a panic, and never a
// value that outgrows its input. The seed corpus is every frame body and record
// object of the shared wire 1.0 vectors (testdata/wire_1_0), read from their
// files through internal/wire10vectors, so a regenerated vector set reseeds the
// fuzzers too instead of leaving a copy behind here.
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
// encoding is stable, or a typed refusal.
func FuzzDecode(f *testing.F) {
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
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			refusedAsOneOf(t, err, decodeRefusals)
			return
		}
		// A value re-encodes deterministically: Encode's own bytes decode, and
		// encoding what they decode to gives the same bytes again. Decode keeps
		// a map's keys in the order they arrived, so the values themselves are
		// not compared: the bytes are what a peer sees.
		encoded := Encode(v)
		again, err := Decode(encoded)
		if err != nil {
			t.Fatalf("Encode's own bytes do not decode: %v (%x)", err, encoded)
		}
		if second := Encode(again); !bytes.Equal(encoded, second) {
			t.Fatalf("re-encoding is not deterministic: %x, then %x", encoded, second)
		}
		if len(encoded) > maxEncodedPerInputByte*len(data)+encodeSlack {
			t.Fatalf("%d input bytes decode to %d encoded bytes", len(data), len(encoded))
		}
	})
}
