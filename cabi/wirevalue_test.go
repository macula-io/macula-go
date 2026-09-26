package main

import (
	"errors"
	"math"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// A payload survives the ABI both ways: JSON in, CBOR, JSON out, unchanged,
// integers exact over the wire's int64 range and bytes in their tagged form.
func TestPayloadRoundTripsExactly(t *testing.T) {
	for _, text := range []string{
		`null`,
		`0`,
		`9223372036854775807`,
		`9007199254740993`,
		`-1`,
		`-9223372036854775808`,
		`1.5`,
		`2.0`,
		`1e+300`,
		`-0.5`,
		`"text"`,
		`"0xab"`,
		`{"$bytes":"AAEC/w=="}`,
		`[1,"two",[3],{"k":null}]`,
		`{"a":{"$bytes":""},"b":-7}`,
		`{"$bytes":"AA==","other":1}`,
	} {
		v, err := payloadFromJSON(text)
		if err != nil {
			t.Errorf("%s: %v", text, err)
			continue
		}
		back, err := payloadFromJSON(string(payloadToJSON(v)))
		if err != nil {
			t.Errorf("%s: the returned JSON %s does not parse: %v", text, payloadToJSON(v), err)
			continue
		}
		if got, want := cbor.Encode(back), cbor.Encode(v); string(got) != string(want) {
			t.Errorf("%s: round trip gives %s", text, payloadToJSON(back))
		}
	}
}

func TestPayloadIntegersAreExact(t *testing.T) {
	v, err := payloadFromJSON(`[9223372036854775807, 9007199254740993, -9223372036854775808, 2.0]`)
	if err != nil {
		t.Fatal(err)
	}
	items, _ := v.AsList()
	for i, want := range []int64{math.MaxInt64, 9007199254740993, math.MinInt64} {
		if got, ok := items[i].AsInt64(); !ok || got != want {
			t.Errorf("%d became %v", want, items[i])
		}
	}
	if f, ok := items[3].AsFloat(); !ok || f != 2 {
		t.Errorf("2.0 became %v, want the float 2", items[3])
	}
	if got := string(payloadToJSON(v)); got != `[9223372036854775807,9007199254740993,-9223372036854775808,2.0]` {
		t.Errorf("out: %s", got)
	}
}

func TestPayloadRefusals(t *testing.T) {
	for _, text := range []string{
		`true`,
		`[false]`,
		`{"$bytes": 1}`,
		`{"$bytes": "not base64!"}`,
		`{"$bytes": "AA"}`,
		`9223372036854775808`,
		`18446744073709551615`,
		`-9223372036854775809`,
		`1e400`,
		`{`,
		`1 2`,
	} {
		_, err := payloadFromJSON(text)
		var ae *abiError
		if !errors.As(err, &ae) || ae.kind != kindInvalidArgument {
			t.Errorf("%s: %v, want invalid_argument", text, err)
		}
	}
	if v, err := payloadFromJSON(""); err != nil || !v.IsNull() {
		t.Errorf(`"" gives %v, %v; want null`, v, err)
	}
}

func TestBytesComeOutTagged(t *testing.T) {
	if got := string(payloadToJSON(cbor.Bytes([]byte{0, 1, 2, 255}))); got != `{"$bytes":"AAEC/w=="}` {
		t.Fatalf("bytes come out as %s", got)
	}
}
