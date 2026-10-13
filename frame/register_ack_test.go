package frame

import (
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// REGISTER_ACK (WIRE_1_0.md section 3.5) is the station's per-hop answer to an
// ADVERTISE, UNADVERTISE, SUBSCRIBE or UNSUBSCRIBE: an advertise kind names the
// record version, a subscribe kind the subscriber, never both; a reason is
// present exactly when the ack refuses.

func registerAck(kind string, extra ...cbor.MapEntry) cbor.Value {
	return registerAckNamed(kind, "acme/echo_v1", extra...)
}

func registerAckNamed(kind, name string, extra ...cbor.MapEntry) cbor.Value {
	entries := []cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(5)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text("register_ack")},
		textEntry("kind", kind),
		bytesEntry("realm", make([]byte, 32)),
		textEntry("name", name),
	}
	return cbor.Map(append(entries, extra...))
}

func TestARegisterAckReadsAsItsKindNamesIt(t *testing.T) {
	version, subscriber := bytesEntry("record_version", make([]byte, 16)), bytesEntry("subscriber", make([]byte, 32))
	accepted, refused := valueEntry("accepted", cbor.Int(1)), valueEntry("accepted", cbor.Int(0))
	for _, c := range []struct {
		name string
		ack  cbor.Value
		want error
	}{
		{"an accepted advertise", registerAck("advertise", version, accepted), nil},
		{"a refused unadvertise", registerAck("unadvertise", version, refused, textEntry("reason", "record_refused")), nil},
		{"an accepted subscribe", registerAck("subscribe", subscriber, accepted), nil},
		{"a refused unsubscribe", registerAck("unsubscribe", subscriber, refused, textEntry("reason", "too_many_realms")), nil},
		{"an advertise naming a subscriber", registerAck("advertise", subscriber, accepted), ErrMalformedFrame},
		{"a subscribe naming a record version", registerAck("subscribe", version, accepted), ErrMalformedFrame},
		{"an advertise naming both", registerAck("advertise", version, subscriber, accepted), ErrMalformedFrame},
		{"an advertise naming neither", registerAck("advertise", accepted), ErrMalformedFrame},
		{"a refusal without a reason", registerAck("advertise", version, refused), ErrMalformedFrame},
		{"an acceptance with a reason", registerAck("advertise", version, accepted, textEntry("reason", "refused")), ErrMalformedFrame},
		{"accepted 2", registerAck("advertise", version, valueEntry("accepted", cbor.Int(2))), ErrMalformedFrame},
		{"a null reason", registerAck("advertise", version, refused, valueEntry("reason", cbor.Null())), ErrMalformedFrame},
		{"an empty name", registerAckNamed("advertise", "", version, accepted), ErrMalformedFrame},
		{"a name of 513 bytes", registerAckNamed("advertise", strings.Repeat("n", 513), version, accepted), ErrMalformedFrame},
		{"a record version of 15 bytes", registerAck("advertise", bytesEntry("record_version", make([]byte, 15)), accepted), ErrMalformedFrame},
	} {
		_, known, err := ReadRegisterAck(c.ack)
		switch {
		case c.want == nil && (err != nil || !known):
			t.Errorf("%s: (%t, %v), want it read", c.name, known, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

// A station's REGISTER_ACK, as RegisterAckFrame builds it, reads back as built;
// the builder refuses what a reader would: an unknown kind, an empty or
// over-long name, and a refusal without a reason it knows.
func TestARegisterAckBuildsAsItReads(t *testing.T) {
	for _, ack := range []RegisterAck{
		{Kind: "advertise", Realm: [32]byte{1}, Name: "acme/echo_v1", RecordVersion: [16]byte{2}, Accepted: true},
		{Kind: "unadvertise", Realm: [32]byte{1}, Name: "acme/echo_v1", RecordVersion: [16]byte{2}, Reason: "record_refused"},
		{Kind: "subscribe", Realm: [32]byte{1}, Name: "acme/topic", Subscriber: [32]byte{3}, Accepted: true},
		{Kind: "unsubscribe", Realm: [32]byte{1}, Name: "acme/topic", Subscriber: [32]byte{3}, Reason: "too_many_realms"},
	} {
		built, err := RegisterAckFrame(ack)
		if err != nil {
			t.Fatalf("%+v: %v", ack, err)
		}
		read, known, err := ReadRegisterAck(built)
		if err != nil || !known || read != ack {
			t.Errorf("built %+v, read back (%+v, %t, %v)", ack, read, known, err)
		}
	}
	for name, ack := range map[string]RegisterAck{
		"an unknown kind":                {Kind: "register", Name: "x", Accepted: true},
		"an empty name":                  {Kind: "advertise", Accepted: true},
		"a name of 513 bytes":            {Kind: "advertise", Name: strings.Repeat("n", 513), Accepted: true},
		"a refusal with no reason":       {Kind: "advertise", Name: "x"},
		"a refusal of an unknown reason": {Kind: "advertise", Name: "x", Reason: "a_reason_from_wire_1_1"},
		"an acceptance with a reason":    {Kind: "advertise", Name: "x", Accepted: true, Reason: "refused"},
	} {
		if _, err := RegisterAckFrame(ack); !errors.Is(err, ErrMalformedFrame) {
			t.Errorf("%s: %v, want ErrMalformedFrame", name, err)
		}
	}
}
