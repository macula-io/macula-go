package cbor

import (
	"encoding/binary"
	"errors"
	"testing"
)

// zerosArray is an array declaring count items, followed by zeros zero items.
func zerosArray(count, zeros int) []byte {
	out := binary.BigEndian.AppendUint32([]byte{0x9a}, uint32(count))
	return append(out, make([]byte, zeros)...)
}

// mapOfEntries is a map of entries distinct integer keys, each with the value 0.
func mapOfEntries(entries int) []byte {
	out := binary.BigEndian.AppendUint32([]byte{0xba}, uint32(entries))
	for k := 1; k <= entries; k++ {
		out = binary.BigEndian.AppendUint32(append(out, 0x1a), uint32(k))
		out = append(out, 0x00)
	}
	return out
}

// pastBudget is an array whose last item is the one past a budget of 131,072
// items.
func pastBudget(item ...byte) []byte {
	return append(zerosArray(131072, 131071), item...)
}

// The element budget counts as macula's decoder counts: every item once, map
// keys, array elements and the top-level value included, after its head and
// argument are read and before its own checks. The verdicts are those of
// macula_record_cbor:decode_strict/2 at 0cbcf64 (merge-11.0.0) with its budget of
// 131,072. A refusal of "refused" holds only the verdict: past the budget,
// macula's reason for a half-width float that is NaN or infinite is malformed,
// where macula-go's is too_many_elements.
func TestDecodeCountsItemsAsTheReferenceDecoderDoes(t *testing.T) {
	if MaxElements != 131072 {
		t.Errorf("MaxElements is %d, want macula's element budget of 131,072", MaxElements)
	}
	cases := []struct {
		name    string
		input   []byte
		refusal string
	}{
		{"an array of 131,071 zeros, 131,072 items", zerosArray(131071, 131071), ""},
		{"an array of 131,072 zeros, 131,073 items", zerosArray(131072, 131072), "too_many_elements"},
		{"a map of 65,535 entries, 131,071 items", mapOfEntries(65535), ""},
		{"a map of 65,536 entries, 131,073 items", mapOfEntries(65536), "too_many_elements"},
		{"a one-item array holding a map of 65,535 entries, 131,072 items", append([]byte{0x81}, mapOfEntries(65535)...), ""},
		{"a one-item array holding a map of 65,536 entries, the item past the budget a key", append([]byte{0x81}, mapOfEntries(65536)...), "too_many_elements"},
		{"the item past the budget is truncated", pastBudget(0x18), "malformed"},
		{"the item past the budget is a truncated half float", pastBudget(0xf9, 0x00), "malformed"},
		{"the item past the budget is a truncated single float", pastBudget(0xfa, 0x00, 0x00), "malformed"},
		{"the item past the budget is false", pastBudget(0xf4), "too_many_elements"},
		{"the item past the budget is null", pastBudget(0xf6), "too_many_elements"},
		{"the item past the budget is a finite half float", pastBudget(0xf9, 0x3e, 0x00), "too_many_elements"},
		{"the item past the budget is a half-width NaN", pastBudget(0xf9, 0x7e, 0x00), "refused"},
		{"the item past the budget is a half-width infinity", pastBudget(0xf9, 0x7c, 0x00), "refused"},
		{"the item past the budget is a single-width NaN", pastBudget(0xfa, 0x7f, 0xc0, 0x00, 0x00), "too_many_elements"},
		{"the item past the budget is a double-width infinity", pastBudget(0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0), "too_many_elements"},
		{"the item past the budget is invalid text", pastBudget(0x61, 0xff), "too_many_elements"},
		{"the item past the budget is an integer above 2^63-1", pastBudget(0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0), "too_many_elements"},
		{"the item past the budget is a tag", pastBudget(0xc1, 0x00), "too_many_elements"},
		{"the item past the budget is simple value 32 in two bytes", pastBudget(0xf8, 0x20), "too_many_elements"},
		{"the item past the budget is simple value 24 with its byte missing", pastBudget(0xf8), "malformed"},
		{"the item past the budget has additional information 28", pastBudget(0x1c), "malformed"},
		{"the item past the budget is an indefinite array", pastBudget(0x9f, 0xff), "malformed"},
		{"the item past the budget is a byte string longer than the input", pastBudget(0x42, 0x00), "too_many_elements"},
		{"the item past the budget is an empty array", pastBudget(0x80), "too_many_elements"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.input)
			switch c.refusal {
			case "":
				if err != nil {
					t.Errorf("%v, but the reference accepts it", err)
				}
			case "refused":
				if err == nil {
					t.Error("accepted, but the reference refuses it")
				}
			default:
				if want := referenceRefusals[c.refusal]; !errors.Is(err, want) {
					t.Errorf("%v, but the reference refuses it as %s", err, c.refusal)
				}
			}
		})
	}
}
