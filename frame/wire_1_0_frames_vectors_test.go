package frame

import (
	"errors"
	"testing"

	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 frame vectors (macula priv/vectors/wire_1_0/frames.json,
// macula#97): one valid frame per frame type, each accepted by the envelope
// rules (ReadEnvelope) and, for a frame this library reads, by that type's own
// reader; and REGISTER_ACK's field-rule negatives, refused as malformed_frame.
// A frame only stations exchange (SWIM, HyParView, Plumtree, the DHT and
// content frames) is held to the envelope rules alone: no reader of its fields
// exists here. Clocks and request context are not part of this class, so a
// signed frame that needs them (a reply, a stream frame) is held to the
// envelope too, and verify, enums and tbs cover its signature.

func TestTheWireOneFrameVectors(t *testing.T) {
	f, err := wire10vectors.Load("frames")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			v := vectorFrame(t, c.Text("frame"))
			envelope, err := ReadEnvelope(v)
			if err == nil {
				err = readFrameFields(t, c, envelope)
			}
			switch c.Outcome() {
			case "accept":
				if err != nil {
					t.Fatalf("%v, want it accepted", err)
				}
			case "refuse":
				if c.Reason() != "malformed_frame" || !errors.Is(err, ErrMalformedFrame) {
					t.Fatalf("%v, want %s", err, c.Reason())
				}
			default:
				t.Fatalf("outcome %q has no check here", c.Outcome())
			}
		})
	}
}

// readFrameFields reads a frame whose envelope is read by its type's own
// reader, where this library has one that needs no context.
func readFrameFields(t *testing.T, c wire10vectors.Case, envelope Envelope) error {
	t.Helper()
	v := envelope.Frame
	switch envelope.FrameType {
	case "advertise", "unadvertise", "subscribe", "unsubscribe", "goodbye":
		_, err := ReadControl(v)
		return err
	case "liveness_ping", "liveness_pong":
		if _, _, ok := LivenessNonce(v); !ok {
			return ErrMalformedFrame
		}
		return nil
	case "register_ack":
		_, known, err := ReadRegisterAck(v)
		if err == nil && !known {
			t.Errorf("a REGISTER_ACK of a kind this library knows was ignored")
		}
		return err
	case "call", "stream_open":
		_, err := VerifyRequest(v, profile.Profile(c.Profile))
		return err
	}
	return nil
}
