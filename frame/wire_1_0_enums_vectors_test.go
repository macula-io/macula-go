package frame

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 enum vectors (macula priv/vectors/wire_1_0/enums.json,
// macula#99) for the frames a client reads: an EVENT's delivered_via per hop,
// and STREAM_OPEN mode, relay error code, STREAM_DATA encoding and STREAM_END
// role inside a signed tbs. HELLO refusal_code runs in package handshake.
// HyParView priority and SWIM state ride frames only stations exchange.

func vectorFrame(t *testing.T, hexFrame string) cbor.Value {
	t.Helper()
	b, err := hex.DecodeString(hexFrame)
	if err != nil {
		t.Fatal(err)
	}
	v, err := cbor.Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func contextFrame(t *testing.T, c wire10vectors.Case, i int) cbor.Value {
	t.Helper()
	list, _ := c.Input["context"].([]any)
	if len(list) <= i {
		t.Fatalf("%s: no context frame %d", c.ID, i)
	}
	s, _ := list[i].(string)
	return vectorFrame(t, s)
}

func stationKeyID(t *testing.T, p profile.Profile) [32]byte {
	t.Helper()
	keys, err := wire10vectors.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	id, err := keys.KeyID(string(p), "station_identity")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestTheWireOneEnumVectors(t *testing.T) {
	f, err := wire10vectors.Load("enums")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			checkEnumVector(t, c)
		})
	}
}

// checkEnumVector holds one enum vector's reader to macula's verdict: the
// value read where the enum is known, the fallback counted where it is not,
// and enum_unknown naming the field where it is refused.
func checkEnumVector(t *testing.T, c wire10vectors.Case) {
	t.Helper()
	field := c.ExpectText("field")
	if field == "" {
		field = enumFieldOf(c.ID)
	}
	skipStationOnlyEnum(t, field)
	p := profile.Profile(c.Profile)
	v := vectorFrame(t, c.Text("frame"))
	before := WireCounters().EnumFallback[field]
	checkEnumOutcome(t, c, field, readEnumVector(t, c, p, field, v))
	counted := WireCounters().EnumFallback[field] > before
	if want := c.ExpectText("count") == "wire_enum_fallback"; counted != want {
		t.Errorf("wire_enum_fallback{%s} counted %t, want %t", field, counted, want)
	}
}

// skipStationOnlyEnum skips a vector for an enum only stations exchange, or a
// HELLO refusal code, which package handshake runs.
func skipStationOnlyEnum(t *testing.T, field string) {
	t.Helper()
	switch field {
	case "priority", "state":
		t.Skip("a HyParView or SWIM frame: only stations exchange it")
	case "refusal_code":
		t.Skip("HELLO: runs in package handshake")
	}
}

// readEnumVector reads the case's frame with the reader its field names, and
// returns that reader's error.
func readEnumVector(t *testing.T, c wire10vectors.Case, p profile.Profile, field string, v cbor.Value) error {
	t.Helper()
	switch field {
	case "delivered_via":
		return readDeliveredVia(t, c, p, v)
	case "mode":
		_, err := VerifyRequest(v, p)
		return err
	case "code":
		return readRelayCode(t, c, p, v)
	case "encoding", "role":
		return readCallerStreamEnum(t, c, p, v)
	case "kind", "reason":
		return readRegisterAckEnum(t, c, v)
	}
	t.Fatalf("no reader for field %q", field)
	return nil
}

// readDeliveredVia reads an EVENT, and holds the value its reader names where
// the read verifies.
func readDeliveredVia(t *testing.T, c wire10vectors.Case, p profile.Profile, v cbor.Value) error {
	t.Helper()
	_, err := VerifyPublication(v, p, c.Int("now_ms"))
	if err == nil {
		if got := DeliveredVia(v); got != c.ExpectText("value") {
			t.Errorf("DeliveredVia = %q, want %q", got, c.ExpectText("value"))
		}
	}
	return err
}

// readRelayCode reads a relay ERROR against the request the vector carries as
// its context.
func readRelayCode(t *testing.T, c wire10vectors.Case, p profile.Profile, v cbor.Value) error {
	t.Helper()
	request, rerr := VerifyRequest(contextFrame(t, c, 0), p)
	if rerr != nil {
		t.Fatalf("the context request: %v", rerr)
	}
	_, err := VerifyRelayError(v, request, p, stationKeyID(t, p))
	return err
}

// readCallerStreamEnum reads a caller's stream frame against the STREAM_OPEN
// the vector carries as its context.
func readCallerStreamEnum(t *testing.T, c wire10vectors.Case, p profile.Profile, v cbor.Value) error {
	t.Helper()
	open, rerr := VerifyRequest(contextFrame(t, c, 0), p)
	if rerr != nil {
		t.Fatalf("the context STREAM_OPEN: %v", rerr)
	}
	state, serr := OpenStream(open)
	if serr != nil {
		t.Fatalf("OpenStream: %v", serr)
	}
	_, _, err := VerifyCallerStream(v, state, p)
	return err
}

// readRegisterAckEnum reads a REGISTER_ACK, holding a kind or reason it knows
// to the vector's: a case that ignores the ack must not have acted on it.
func readRegisterAckEnum(t *testing.T, c wire10vectors.Case, v cbor.Value) error {
	t.Helper()
	ack, known, err := ReadRegisterAck(v)
	switch {
	case err != nil:
	case c.Outcome() == "ignore" && known:
		t.Errorf("an ack of kind %q was acted on, want it ignored", ack.Kind)
	case c.Outcome() != "ignore" && ack.Reason != c.ExpectText("value"):
		t.Errorf("reason = %q, want %q", ack.Reason, c.ExpectText("value"))
	}
	return err
}

// checkEnumOutcome holds the reader's error to the case's verdict, and a
// refusal to enum_unknown naming the field the case exercises.
func checkEnumOutcome(t *testing.T, c wire10vectors.Case, field string, err error) {
	t.Helper()
	switch c.Outcome() {
	case "accept", "fallback", "ignore":
		if err != nil {
			t.Fatalf("%v, want it read", err)
		}
	case "refuse":
		var unknown *EnumUnknownError
		if c.Reason() != "enum_unknown" || !errors.As(err, &unknown) || unknown.Field != field {
			t.Fatalf("%v, want %s naming %s", err, c.Reason(), field)
		}
	default:
		t.Fatalf("outcome %q has no check here", c.Outcome())
	}
}

// enumFieldOf names the field a case without expect.field tests, from its id
// (enum.<name>.…): relay_code is the relay error's code.
func enumFieldOf(id string) string {
	name, _, _ := strings.Cut(strings.TrimPrefix(id, "enum."), ".")
	if name == "relay_code" {
		return "code"
	}
	return name
}
