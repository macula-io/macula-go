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

// The wire 1.0 enum vectors (macula test/vectors/wire_1_0/enums.json,
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
			field := c.ExpectText("field")
			if field == "" {
				field = enumFieldOf(c.ID)
			}
			switch field {
			case "priority", "state":
				t.Skip("a HyParView or SWIM frame: only stations exchange it")
			case "refusal_code":
				t.Skip("HELLO: runs in package handshake")
			}
			p := profile.Profile(c.Profile)
			v := vectorFrame(t, c.Text("frame"))
			before := WireCounters().EnumFallback[field]
			var err error
			switch field {
			case "delivered_via":
				if _, err = VerifyPublication(v, p, c.Int("now_ms")); err == nil {
					if got := DeliveredVia(v); got != c.ExpectText("value") {
						t.Errorf("DeliveredVia = %q, want %q", got, c.ExpectText("value"))
					}
				}
			case "mode":
				_, err = VerifyRequest(v, p)
			case "code":
				request, rerr := VerifyRequest(contextFrame(t, c, 0), p)
				if rerr != nil {
					t.Fatalf("the context request: %v", rerr)
				}
				_, err = VerifyRelayError(v, request, p, stationKeyID(t, p))
			case "encoding", "role":
				open, rerr := VerifyRequest(contextFrame(t, c, 0), p)
				if rerr != nil {
					t.Fatalf("the context STREAM_OPEN: %v", rerr)
				}
				state, serr := OpenStream(open)
				if serr != nil {
					t.Fatalf("OpenStream: %v", serr)
				}
				_, _, err = VerifyCallerStream(v, state, p)
			default:
				t.Fatalf("no reader for field %q", field)
			}
			switch c.Outcome() {
			case "accept", "fallback":
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
			counted := WireCounters().EnumFallback[field] > before
			if want := c.ExpectText("count") == "wire_enum_fallback"; counted != want {
				t.Errorf("wire_enum_fallback{%s} counted %t, want %t", field, counted, want)
			}
		})
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
