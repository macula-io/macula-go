package frame

import (
	"errors"
	"math"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// checkFrameWithPayload is a frame's map around payload: frame_type and
// payload, which adds 4 items to the payload's own.
func checkFrameWithPayload(payload cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("frame_type"), Val: cbor.Text("result")},
		{Key: cbor.Text("payload"), Val: payload},
	})
}

// checkFrameNestedLists is depth lists, each inside the one before.
func checkFrameNestedLists(depth int) cbor.Value {
	v := cbor.List(nil)
	for range depth - 1 {
		v = cbor.List([]cbor.Value{v})
	}
	return v
}

// A whole frame of cbor.MaxElements items is sendable and one more item is
// not, however the items fall between its payload and its own fields.
func TestCheckFrameHoldsAWholeFrameToTheElementBudget(t *testing.T) {
	atBudget := checkFrameWithPayload(zerosList(cbor.MaxElements - 5))
	if n := itemCount(atBudget); n != cbor.MaxElements {
		t.Fatalf("the frame at the budget holds %d items, want %d", n, cbor.MaxElements)
	}
	if err := CheckFrame(atBudget); err != nil {
		t.Errorf("a frame of %d items: %v, want it sendable", cbor.MaxElements, err)
	}
	over := checkFrameWithPayload(zerosList(cbor.MaxElements - 4))
	if err := CheckFrame(over); !errors.Is(err, ErrFrameBreaksDecodingRule) {
		t.Errorf("a frame of %d items: %v, want ErrFrameBreaksDecodingRule", cbor.MaxElements+1, err)
	}
}

// A whole frame may nest cbor.MaxNestingDepth levels, its own map counted, and
// not one more.
func TestCheckFrameHoldsAWholeFrameToTheNestingDepth(t *testing.T) {
	deepest := checkFrameWithPayload(checkFrameNestedLists(cbor.MaxNestingDepth - 1))
	if err := CheckFrame(deepest); err != nil {
		t.Errorf("a frame nesting %d levels: %v, want it sendable", cbor.MaxNestingDepth, err)
	}
	tooDeep := checkFrameWithPayload(checkFrameNestedLists(cbor.MaxNestingDepth))
	if err := CheckFrame(tooDeep); !errors.Is(err, ErrFrameBreaksDecodingRule) {
		t.Errorf("a frame nesting %d levels: %v, want ErrFrameBreaksDecodingRule", cbor.MaxNestingDepth+1, err)
	}
}

// CheckFrame refuses what the decoding rule refuses anywhere in the frame, its
// own fields included.
func TestCheckFrameRefusesWhatTheDecodingRuleRefusesAnywhereInTheFrame(t *testing.T) {
	frames := map[string]cbor.Value{
		"a byte-string key among the frame's fields": cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("frame_type"), Val: cbor.Text("result")},
			{Key: cbor.Bytes([]byte("payload")), Val: cbor.Null()},
		}),
		"two frame fields with one wire key": cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("frame_type"), Val: cbor.Text("result")},
			{Key: cbor.Text("frame_type"), Val: cbor.Text("error")},
		}),
		"text that is not UTF-8 in the payload": checkFrameWithPayload(cbor.Text("\xff")),
		"a NaN in the payload":                  checkFrameWithPayload(cbor.Float(math.NaN())),
	}
	for name, v := range frames {
		if err := CheckFrame(v); !errors.Is(err, ErrFrameBreaksDecodingRule) {
			t.Errorf("%s: CheckFrame = %v, want ErrFrameBreaksDecodingRule", name, err)
		}
	}
}

// Encode refuses a frame over the frame cap with an error wrapping
// ErrFrameTooLarge.
func TestEncodeRefusesAFrameOverTheCapWithItsOwnError(t *testing.T) {
	if _, err := Encode(checkFrameWithPayload(cbor.Bytes(make([]byte, MaxFrameBytes)))); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("Encode = %v, want ErrFrameTooLarge", err)
	}
}
