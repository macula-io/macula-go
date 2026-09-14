package cbor

import (
	"bytes"
	"errors"
	"testing"
)

// listOfOnes is the encoding of a list of n one-byte integers.
func listOfOnes(n int) []byte {
	out := appendHead(nil, majorList, uint64(n))
	return append(out, bytes.Repeat([]byte{0x01}, n)...)
}

// mapOfDistinctKeys is the encoding of a map of n entries, each a distinct
// integer key with a one-byte integer value.
func mapOfDistinctKeys(n int) []byte {
	out := appendHead(nil, majorMap, uint64(n))
	for i := range n {
		out = appendHead(out, majorUInt, uint64(i))
		out = append(out, 0x01)
	}
	return out
}

// A list of MaxElements items is MaxElements+1 values with the list itself,
// one past the budget, and is refused however few bytes each item takes.
func TestDecodeRefusesAValueOfMoreThanMaxElementsValues(t *testing.T) {
	if _, _, err := Decode(listOfOnes(MaxElements)); !errors.Is(err, ErrTooManyElements) {
		t.Fatalf("a list of MaxElements one-byte items: err %v, want ErrTooManyElements", err)
	}
}

// A list one item shorter is exactly MaxElements values, and decodes.
func TestDecodeAcceptsAValueOfExactlyMaxElementsValues(t *testing.T) {
	if _, _, err := Decode(listOfOnes(MaxElements - 1)); err != nil {
		t.Fatalf("a list of MaxElements-1 one-byte items: %v", err)
	}
}

// A map's keys and values each count, so a map of MaxElements/2 entries is
// one value past the budget with the map itself.
func TestDecodeCountsAMapsKeysAndValuesAgainstMaxElements(t *testing.T) {
	if _, _, err := Decode(mapOfDistinctKeys(MaxElements / 2)); !errors.Is(err, ErrTooManyElements) {
		t.Fatalf("a map of MaxElements/2 entries: err %v, want ErrTooManyElements", err)
	}
}
