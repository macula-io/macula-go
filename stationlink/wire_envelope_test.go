package stationlink

import (
	"errors"
	"maps"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// Wire 1.0 on the control stream (macula docs/design/WIRE_1_0.md sections 3.2
// and 3.3): a frame of an unknown type, or one carrying an unknown critical
// extension, is dropped and counted, and the link stays up. A frame whose
// envelope does not decode under the wire 1.0 rules still ends it.

func controlFrame(frameType string, extra ...cbor.MapEntry) []byte {
	return cbor.Encode(cbor.Map(append([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(5)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text(frameType)},
	}, extra...)))
}

// stillUp proves the link read past what came before: it answers a
// liveness_ping sent after it.
func stillUp(t *testing.T, s *testStation) {
	t.Helper()
	nonce := [16]byte{7, 7}
	s.send(cbor.Encode(frame.LivenessPingFrame(nonce)))
	if frameType, got, ok := frame.LivenessNonce(decodeFrame(t, s.next())); !ok || frameType != "liveness_pong" || got != nonce {
		t.Fatalf("after the frame: (%q, %x, %t), want the link up and answering", frameType, got, ok)
	}
}

func TestAFrameOfAnUnknownTypeIsCountedAndTheLinkStaysUp(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "unknown frame type station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	before := frame.WireCounters().UnknownFrameType
	s.send(controlFrame("frame_from_wire_1_1", cbor.MapEntry{Key: cbor.Text("anything"), Val: cbor.Int(1)}))
	stillUp(t, s)
	if got := frame.WireCounters().UnknownFrameType; got != before+1 {
		t.Errorf("wire_unknown_frame_type = %d, want %d", got, before+1)
	}
	if err := link.Err(); err != nil {
		t.Errorf("the link ended: %v", err)
	}
}

func TestAFrameWithAnUnknownCriticalExtensionIsDroppedAndTheLinkStaysUp(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "critical extension station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	ext := cbor.MapEntry{Key: cbor.Text("ext"), Val: cbor.Map([]cbor.MapEntry{{
		Key: cbor.Text("no_such.extension"),
		Val: cbor.Map([]cbor.MapEntry{{Key: cbor.Text("critical"), Val: cbor.Int(1)}, {Key: cbor.Text("value"), Val: cbor.Int(1)}}),
	}})}
	goodbye := controlFrame("goodbye", ext, cbor.MapEntry{Key: cbor.Text("reason"), Val: cbor.Text("normal")})
	s.send(goodbye)
	stillUp(t, s)
	if got := link.Unrouted()["extension_unsupported"]; got != 1 {
		t.Errorf("unrouted %v, want one extension_unsupported", link.Unrouted())
	}
}

func TestAFrameOfAnotherVersionEndsTheLink(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "version 2 frame station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	s.send(cbor.Encode(cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(2)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text("frame_from_wire_0")},
	})))
	if err := waitDone(t, link); !errors.Is(err, frame.ErrMalformedFrame) {
		t.Errorf("a version 2 frame ended the link with %v, want ErrMalformedFrame", err)
	}
}

// A REGISTER_ACK (WIRE_1_0.md section 3.5) is a frame the link reads: a
// refusal is counted by its reason, an unknown reason as refused, an ack of an
// unknown kind ignored, and the link stays up through each.
func TestARefusingRegisterAckIsCountedByReasonAndTheLinkStaysUp(t *testing.T) {
	s := startTestStationAs(t, profile.PQPure, "register ack station")
	link, err := dial(t, s, newClient(t, profile.PQPure))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	ack := func(kind, reason string) []byte {
		return controlFrame("register_ack",
			cbor.MapEntry{Key: cbor.Text("kind"), Val: cbor.Text(kind)},
			cbor.MapEntry{Key: cbor.Text("realm"), Val: cbor.Bytes(make([]byte, 32))},
			cbor.MapEntry{Key: cbor.Text("name"), Val: cbor.Text("acme/echo_v1")},
			cbor.MapEntry{Key: cbor.Text("record_version"), Val: cbor.Bytes(make([]byte, 16))},
			cbor.MapEntry{Key: cbor.Text("accepted"), Val: cbor.Int(0)},
			cbor.MapEntry{Key: cbor.Text("reason"), Val: cbor.Text(reason)})
	}
	s.send(ack("advertise", "too_many_providers"))
	s.send(ack("advertise", "a_reason_from_wire_1_1"))
	s.send(ack("a_kind_from_wire_1_1", "too_many_providers"))
	stillUp(t, s)
	want := map[string]uint64{"too_many_providers": 1, "refused": 1}
	if got := link.RegisterRefusals(); !maps.Equal(got, want) {
		t.Errorf("register refusals %v, want %v", got, want)
	}
	if err := link.Err(); err != nil {
		t.Errorf("the link ended: %v", err)
	}
}
