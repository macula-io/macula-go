package frame

import (
	"math"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

func TestCheckPayloadAcceptsOrdinaryValues(t *testing.T) {
	cases := []cbor.Value{
		cbor.Null(),
		cbor.Text("hello"),
		cbor.Uint64(42),
		cbor.Bytes([]byte("hi")),
		cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("a"), Val: cbor.Uint64(1)},
			{Key: cbor.Text("b"), Val: cbor.Text("two")},
		}),
		cbor.List([]cbor.Value{cbor.Uint64(1), cbor.Uint64(2), cbor.Uint64(3)}),
	}
	for i, v := range cases {
		if err := CheckPayload(v); err != nil {
			t.Errorf("case %d: CheckPayload(%v) = %v, want nil", i, v, err)
		}
	}
}

func TestCheckPayloadRejectsDuplicateKeys(t *testing.T) {
	v := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("dup"), Val: cbor.Uint64(1)},
		{Key: cbor.Text("dup"), Val: cbor.Uint64(2)},
	})
	err := CheckPayload(v)
	if err == nil {
		t.Fatalf("expected an error for duplicate map keys, got nil")
	}
	if !strings.Contains(err.Error(), "same wire key") {
		t.Errorf("error = %q, want it to mention the same-wire-key collision", err.Error())
	}
}

func TestCheckPayloadRejectsDuplicateKeysNested(t *testing.T) {
	v := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("outer"), Val: cbor.List([]cbor.Value{
			cbor.Map([]cbor.MapEntry{
				{Key: cbor.Text("inner"), Val: cbor.Uint64(1)},
				{Key: cbor.Text("inner"), Val: cbor.Uint64(2)},
			}),
		})},
	})
	if err := CheckPayload(v); err == nil {
		t.Fatalf("expected an error for a nested duplicate key, got nil")
	}
}

func TestCheckPayloadRejectsOversizedPayload(t *testing.T) {
	big := make([]byte, MaxFrameBytes+1)
	err := CheckPayload(cbor.Bytes(big))
	if err == nil {
		t.Fatalf("expected an error for an oversized payload, got nil")
	}
	if !strings.Contains(err.Error(), "frame cap") {
		t.Errorf("error = %q, want it to mention the frame cap", err.Error())
	}
}

func TestCheckPayloadAllowsFiniteFloats(t *testing.T) {
	cases := []float64{0, 1.5, -1.5, 1e300}
	for _, f := range cases {
		if err := CheckPayload(cbor.Float(f)); err != nil {
			t.Errorf("CheckPayload(Float(%v)) = %v, want nil", f, err)
		}
	}
}

func TestCheckPayloadRejectsNonFiniteFloats(t *testing.T) {
	// Deliberate DIVERGENCE from macula_frame.erl's own check_value/2,
	// which passes every float through unconditionally -- see
	// CheckPayload's own doc on why that's safe in Erlang (a BEAM float
	// can never BE non-finite) and not in Go (float64 can).
	cases := []float64{math.NaN(), math.Inf(1), math.Inf(-1)}
	for _, f := range cases {
		if err := CheckPayload(cbor.Float(f)); err == nil {
			t.Errorf("CheckPayload(Float(%v)) = nil, want an error", f)
		}
	}
}

func TestCheckPayloadRejectsNonFiniteFloatNestedInsideAMapValue(t *testing.T) {
	v := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("x"), Val: cbor.Float(math.NaN())},
	})
	if err := CheckPayload(v); err == nil {
		t.Fatalf("expected an error for a non-finite float nested inside a map value, got nil")
	}
}

func TestCheckPayloadRejectsUnsupportedKeyKind(t *testing.T) {
	v := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Float(1.5), Val: cbor.Uint64(1)},
	})
	if err := CheckPayload(v); err == nil {
		t.Fatalf("expected an error for a float map key, got nil")
	}
}
