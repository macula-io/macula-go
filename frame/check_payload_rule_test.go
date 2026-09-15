package frame

import (
	"math"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// nestedLists is levels one-item lists around a uint 0.
func nestedLists(levels int) cbor.Value {
	v := cbor.Uint64(0)
	for range levels {
		v = cbor.List([]cbor.Value{v})
	}
	return v
}

// inFrameMap is payload as the value of one field of a map, the way a payload
// travels inside a frame.
func inFrameMap(payload cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("payload"), Val: payload}})
}

func oneEntry(key, val cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: key, Val: val}})
}

// payloadsTheRuleRefuses are payloads whose frame the decoding rule refuses.
var payloadsTheRuleRefuses = []struct {
	name    string
	payload cbor.Value
}{
	{"a byte string key", oneEntry(cbor.Bytes([]byte("a")), cbor.Uint64(1))},
	{"a float key", oneEntry(cbor.Float(1.5), cbor.Uint64(1))},
	{"a duplicate key", cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Uint64(1)},
		{Key: cbor.Text("a"), Val: cbor.Uint64(2)},
	})},
	{"an unsigned integer above 2^63-1", cbor.Uint64(1 << 63)},
	{"an unsigned integer key above 2^63-1", oneEntry(cbor.Uint64(1<<63), cbor.Null())},
	{"a negative integer below -2^63", cbor.NegInt(1 << 63)},
	{"a negative integer key below -2^63", oneEntry(cbor.NegInt(1<<63), cbor.Null())},
	{"text that is not valid UTF-8", cbor.Text("\xff")},
	{"a text key that is not valid UTF-8", oneEntry(cbor.Text("\xff"), cbor.Null())},
	{"a NaN float", cbor.Float(math.NaN())},
	{"64 nested lists", nestedLists(64)},
	{"63 nested lists inside a map", oneEntry(cbor.Text("a"), nestedLists(63))},
}

// payloadsTheRuleAccepts are payloads at the edges of what the decoding rule
// accepts.
var payloadsTheRuleAccepts = []struct {
	name    string
	payload cbor.Value
}{
	{"63 nested lists", nestedLists(63)},
	{"62 nested lists inside a map", oneEntry(cbor.Text("a"), nestedLists(62))},
	{"the largest integer, 2^63-1", cbor.Uint64(1<<63 - 1)},
	{"the smallest integer, -2^63", cbor.NegInt(1<<63 - 1)},
	{"integer keys of both signs", cbor.Map([]cbor.MapEntry{
		{Key: cbor.Int(1), Val: cbor.Null()},
		{Key: cbor.Int(-1), Val: cbor.Null()},
	})},
	{"multibyte text in a key and a value", oneEntry(cbor.Text("café"), cbor.Text("été"))},
	{"a byte string value", oneEntry(cbor.Text("a"), cbor.Bytes([]byte{0xff, 0x00}))},
	{"a finite float", cbor.Float(-1.5)},
}

// A payload the decoding rule would refuse on arrival is refused before it is
// sent, and one the rule accepts is not, so the check and the rule agree.
func TestCheckPayloadRefusesWhatTheDecodingRuleRefuses(t *testing.T) {
	for _, c := range payloadsTheRuleRefuses {
		t.Run(c.name, func(t *testing.T) {
			if _, err := cbor.Decode(cbor.Encode(inFrameMap(c.payload))); err == nil {
				t.Fatalf("the decoding rule accepts a frame carrying this payload, so the case is wrong")
			}
			if err := CheckPayload(c.payload); err == nil {
				t.Errorf("CheckPayload accepted a payload whose frame the decoding rule refuses")
			}
		})
	}
}

func TestCheckPayloadAcceptsWhatTheDecodingRuleAccepts(t *testing.T) {
	for _, c := range payloadsTheRuleAccepts {
		t.Run(c.name, func(t *testing.T) {
			if _, err := cbor.Decode(cbor.Encode(inFrameMap(c.payload))); err != nil {
				t.Fatalf("the decoding rule refuses a frame carrying this payload (%v), so the case is wrong", err)
			}
			if err := CheckPayload(c.payload); err != nil {
				t.Errorf("CheckPayload: %v, for a payload whose frame the decoding rule accepts", err)
			}
		})
	}
}
