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
