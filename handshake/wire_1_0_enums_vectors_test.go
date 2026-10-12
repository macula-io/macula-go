package handshake

import (
	"errors"
	"testing"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/internal/wire10vectors"
)

// The wire 1.0 enum vectors for HELLO's refusal_code (macula
// test/vectors/wire_1_0/enums.json): a per-hop enum, so a code this library
// does not know reads as not_accepted, counted.
func TestTheWireOneRefusalCodeVectors(t *testing.T) {
	f, err := wire10vectors.Load("enums")
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	for _, c := range f.Cases {
		if c.ExpectText("field") != "refusal_code" {
			continue
		}
		ran++
		t.Run(c.ID, func(t *testing.T) {
			hello, err := c.Hex("frame")
			if err != nil {
				t.Fatal(err)
			}
			before := frame.WireCounters().EnumFallback["refusal_code"]
			_, err = ReadHello(hello, Station{})
			var refused *RefusedError
			if !errors.As(err, &refused) || string(refused.Code) != c.ExpectText("value") {
				t.Fatalf("ReadHello: %v, want a refusal read as %s", err, c.ExpectText("value"))
			}
			counted := frame.WireCounters().EnumFallback["refusal_code"] > before
			if want := c.ExpectText("count") == "wire_enum_fallback"; counted != want {
				t.Errorf("wire_enum_fallback{refusal_code} counted %t, want %t", counted, want)
			}
		})
	}
	if ran != 2 {
		t.Errorf("%d refusal_code cases, want 2", ran)
	}
}
