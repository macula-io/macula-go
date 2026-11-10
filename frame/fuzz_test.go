package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/internal/wire10vectors"
)

// FuzzDecode holds the frame decoder to macula-go#39's invariant on any byte
// string a peer can send: a complete frame that re-encodes deterministically, a
// frame still needing bytes, or a typed refusal — never a panic, and never a
// frame that outgrows its input. The seed corpus is every frame body of the
// shared wire 1.0 vectors, length-prefixed here as a station sends it, read from
// their files rather than restated.
//
// A hang is the package test timeout: Decode refuses a length over
// MaxFrameBytes before it reads the body, and the CBOR decoder behind it bounds
// its own work.

// frameRefusals are every error Decode can return: the frame cap, and the
// CBOR decoding rule's refusals, which Decode wraps.
var frameRefusals = []error{
	ErrFrameTooLarge,
	cbor.ErrMalformed,
	cbor.ErrTrailingBytes,
	cbor.ErrBadKey,
	cbor.ErrDuplicateKey,
	cbor.ErrInvalidText,
	cbor.ErrNestingTooDeep,
	cbor.ErrIntegerOutOfRange,
	cbor.ErrTooManyElements,
}

// maxEncodedPerInputByte and encodeSlack bound what one input byte may encode
// to, with slack for the head and the length prefix.
const (
	maxEncodedPerInputByte = 32
	encodeSlack            = 64
)

// FuzzDecode holds Decode to the invariant.
func FuzzDecode(f *testing.F) {
	for _, body := range []struct{ class, field string }{
		{"frames", "frame"},
		{"envelope", "frame"},
	} {
		seeds, err := wire10vectors.HexInputs(body.class, body.field)
		if err != nil {
			f.Fatalf("%s: %v", body.class, err)
		}
		for _, seed := range seeds {
			f.Add(lengthPrefixed(seed))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(data)
		if err != nil {
			for _, refusal := range frameRefusals {
				if errors.Is(err, refusal) {
					return
				}
			}
			t.Fatalf("refused with an error that is not typed: %v", err)
		}
		if !decoded.Complete {
			if decoded.NeedMore <= 0 {
				t.Fatalf("an incomplete frame needing %d more bytes", decoded.NeedMore)
			}
			return
		}
		if decoded.Consumed < 4 || decoded.Consumed > len(data) {
			t.Fatalf("consumed %d of %d bytes", decoded.Consumed, len(data))
		}
		// The frame it read encodes again, and decoding that encoding gives a
		// frame that encodes to the same bytes: what a peer is sent is stable.
		encoded, err := Encode(decoded.Frame)
		if err != nil {
			t.Fatalf("a decoded frame does not encode: %v", err)
		}
		if int(binary.BigEndian.Uint32(encoded)) != len(encoded)-4 {
			t.Fatalf("an encoding whose length prefix does not count its body: %x", encoded)
		}
		again, err := Decode(encoded)
		if err != nil || !again.Complete {
			t.Fatalf("Encode's own frame does not decode: %v", err)
		}
		second, err := Encode(again.Frame)
		if err != nil {
			t.Fatalf("a re-decoded frame does not encode: %v", err)
		}
		if !bytes.Equal(encoded, second) {
			t.Fatalf("re-encoding is not deterministic: %x, then %x", encoded, second)
		}
		// Nothing a frame carries outgrows the bytes that carried it: the
		// widest item this encoding writes is nine bytes for a three-byte
		// half-float, and every item costs at least one byte to send.
		if len(encoded) > maxEncodedPerInputByte*len(data)+encodeSlack {
			t.Fatalf("%d input bytes carry a %d-byte frame", len(data), len(encoded))
		}
	})
}

// lengthPrefixed is body as a station sends it: its length in four big-endian
// bytes, then the body.
func lengthPrefixed(body []byte) []byte {
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(len(body)))
	copy(out[4:], body)
	return out
}
