package stationlink

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/internal/wire10vectors"
)

// The wire 1.0 envelope vectors (macula priv/vectors/wire_1_0/envelope.json,
// macula#99): what a link does with each frame after HELLO, on the control
// stream or a dedicated stream, and with a length header alone.

// envelopeVerdict is what the link does with one received frame, in the
// vectors' terms.
func envelopeVerdict(t *testing.T, c wire10vectors.Case) (outcome, reason string, quicCode int64) {
	t.Helper()
	if c.Text("length_header") != "" {
		header, err := c.Hex("length_header")
		if err != nil {
			t.Fatal(err)
		}
		_, err = frameReader{r: bytes.NewReader(header)}.read(MaxFrameBytes)
		if errors.Is(err, ErrFrameTooLarge) {
			return "refuse", "frame_too_large", 0
		}
		return "accept", "", 0
	}
	payload, err := c.Hex("frame")
	if err != nil {
		t.Fatal(err)
	}
	if c.Text("position") == "dedicated_stream" {
		v, err := cbor.Decode(payload)
		if err == nil && unknownOnStream(v) {
			return "abort_stream", "", int64(quicCodeUnknownFrameType)
		}
		return "accept", "", 0
	}
	_, known, err := readControl(payload)
	switch {
	case errors.Is(err, frame.ErrExtensionUnsupported):
		return "refuse", "extension_unsupported", 0
	case err != nil:
		return "refuse", "malformed_frame", 0
	case !known:
		return "ignore", "", 0
	}
	return "accept", "", 0
}

func TestTheWireOneEnvelopeVectors(t *testing.T) {
	f, err := wire10vectors.Load("envelope")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			before := frame.WireCounters()
			outcome, reason, code := envelopeVerdict(t, c)
			after := frame.WireCounters()
			if outcome != c.Outcome() || reason != c.Reason() {
				t.Errorf("verdict (%s, %s), want (%s, %s)", outcome, reason, c.Outcome(), c.Reason())
			}
			if want := c.ExpectInt("quic_code"); want != 0 && code != want {
				t.Errorf("QUIC code %d, want %d", code, want)
			}
			switch c.ExpectText("count") {
			case "wire_unknown_frame_type":
				if after.UnknownFrameType == before.UnknownFrameType {
					t.Errorf("wire_unknown_frame_type did not count")
				}
			case "wire_ext_ignored":
				if sum(after.ExtIgnored) == sum(before.ExtIgnored) {
					t.Errorf("wire_ext_ignored did not count")
				}
			case "wire_ext_refused":
				if sum(after.ExtRefused) == sum(before.ExtRefused) {
					t.Errorf("wire_ext_refused did not count")
				}
			}
		})
	}
}

func sum(m map[string]uint64) (n uint64) {
	for _, v := range m {
		n += v
	}
	return n
}
