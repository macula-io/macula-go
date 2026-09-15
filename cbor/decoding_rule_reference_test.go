package cbor

import (
	"errors"
	"strings"
	"testing"
)

// nestedHex is count one-item arrays around innermost, as hex.
func nestedHex(count int, innermost string) string {
	return strings.Repeat("81", count) + innermost
}

// referenceVerdicts are inputs with the verdict macula's reference decoder,
// macula_record_cbor:decode_strict/1, gives each: the cases its own tests pin,
// and edge cases the shared vectors leave out, among them where nesting is
// counted and which check wins when an input breaks two. refusal is the
// reference's reason, or empty when it accepts.
var referenceVerdicts = []struct {
	name    string
	hex     string
	refusal string
}{
	{"a duplicate key at the top level", "a2616101616102", "duplicate_key"},
	{"a duplicate key in a nested map", "a16162a2616101616102", "duplicate_key"},
	{"a duplicate key in a map inside an array", "81a2616101616102", "duplicate_key"},
	{"bytes after the top-level item", "a161610100", "trailing_bytes"},
	{"bytes after a nested item", "810000", "trailing_bytes"},
	{"truncated input", "a26161", "malformed"},
	{"empty input", "", "malformed"},
	{"invalid UTF-8 in a text value", "a1616161ff", "invalid_text"},
	{"invalid UTF-8 in a text key", "a161ff01", "invalid_text"},
	{"valid multibyte text", "a1616b65636166c3a9", ""},
	{"a UTF-16 surrogate in text", "63eda080", "invalid_text"},
	{"an overlong NUL in text", "62c080", "invalid_text"},
	{"a code point above U+10FFFF", "64f4908080", "invalid_text"},
	{"the noncharacter U+FFFE", "63efbfbe", ""},
	{"a byte string key", "a1416101", "bad_key"},
	{"a float key", "a1f93ff001", "bad_key"},
	{"a half float key", "a1f93c0001", "bad_key"},
	{"an array key", "a18001", "bad_key"},
	{"a map key", "a1a001", "bad_key"},
	{"a null key", "a1f601", "bad_key"},
	{"integer keys 1 and -1", "a201022003", ""},
	{"integer keys -1 and 0", "a220010002", ""},
	{"a duplicate integer key", "a201020103", "duplicate_key"},
	{"the empty text key twice", "a260016002", "duplicate_key"},
	{"a text key in two widths", "a261610178016102", "duplicate_key"},
	{"a text key in one-byte and two-byte widths", "a278016101790001616102", "duplicate_key"},
	{"an unsigned key in two widths", "a20101180102", "duplicate_key"},
	{"a negative key in two widths", "a22001380002", "duplicate_key"},
	{"a duplicate key whose second value is invalid text", "a2616101616161ff", "invalid_text"},
	{"a byte string key whose value nests 65 containers", "a14161" + nestedHex(65, "00"), "too_deep"},
	{"a half float value", "81f93e00", ""},
	{"negative zero, half width", "f98000", ""},
	{"the smallest half subnormal", "f90001", ""},
	{"64 nested arrays", nestedHex(64, "00"), ""},
	{"65 nested arrays", nestedHex(65, "00"), "too_deep"},
	{"64 containers, the innermost an empty array", nestedHex(63, "80"), ""},
	{"65 containers, the innermost an empty array", nestedHex(64, "80"), "too_deep"},
	{"64 containers, the innermost an empty map", nestedHex(63, "a0"), ""},
	{"65 containers, the innermost an empty map", nestedHex(64, "a0"), "too_deep"},
	{"a map whose value is 63 arrays deep", "a16161" + nestedHex(63, "00"), ""},
	{"a map whose value is 64 arrays deep", "a16161" + nestedHex(64, "00"), "too_deep"},
	{"the smallest integer, -2^63", "3b7fffffffffffffff", ""},
	{"an integer below -2^63", "3b8000000000000000", "integer_out_of_range"},
	{"the smallest CBOR integer, -2^64", "3bffffffffffffffff", "integer_out_of_range"},
	{"the largest integer, 2^63-1", "1b7fffffffffffffff", ""},
	{"an integer above 2^63-1", "1b8000000000000000", "integer_out_of_range"},
	{"the largest CBOR integer, 2^64-1", "1bffffffffffffffff", "integer_out_of_range"},
	{"positive infinity, half width", "f97c00", "malformed"},
	{"negative infinity, half width", "f9fc00", "malformed"},
	{"NaN, half width", "f97e00", "malformed"},
	{"positive infinity, single width", "fa7f800000", "malformed"},
	{"negative infinity, single width", "faff800000", "malformed"},
	{"NaN, single width", "fa7fc00000", "malformed"},
	{"positive infinity, double width", "fb7ff0000000000000", "malformed"},
	{"negative infinity, double width", "fbfff0000000000000", "malformed"},
	{"NaN, double width", "fb7ff8000000000000", "malformed"},
	{"an indefinite byte string", "5f4161ff", "malformed"},
	{"an indefinite array", "9f01ff", "malformed"},
	{"an indefinite map", "bf616101ff", "malformed"},
	{"a lone break byte", "ff", "malformed"},
	{"additional info 28", "1c", "malformed"},
	{"additional info 29", "1d", "malformed"},
	{"additional info 30", "1e", "malformed"},
	{"a byte string longer than the input", "4200", "malformed"},
	{"a text length of 2^64-1", "7bffffffffffffffff", "malformed"},
	{"a map claiming 2^64-1 entries", "bbffffffffffffffff", "malformed"},
	{"an array claiming 2^32-1 items", "9affffffff", "malformed"},
	{"a byte string length in eight bytes", "5b000000000000000100", ""},
	{"tag 0 on text", "c060", "malformed"},
	{"tag 1", "c11a00000001", "malformed"},
	{"tag 2, a bignum", "c24101", "malformed"},
	{"simple value 0", "e0", "malformed"},
	{"simple value 19", "f3", "malformed"},
	{"the simple value false", "f4", "malformed"},
	{"the simple value true", "f5", "malformed"},
	{"the simple value undefined", "f7", "malformed"},
	{"simple value 24 in two bytes", "f818", "malformed"},
	{"simple value 32", "f820", "malformed"},
	{"null", "f6", ""},
}

// referenceRefusals is this package's error for each reason the reference
// decoder gives.
var referenceRefusals = map[string]error{
	"trailing_bytes":       ErrTrailingBytes,
	"bad_key":              ErrBadKey,
	"duplicate_key":        ErrDuplicateKey,
	"invalid_text":         ErrInvalidText,
	"too_deep":             ErrNestingTooDeep,
	"integer_out_of_range": ErrIntegerOutOfRange,
	"malformed":            ErrMalformed,
}

func TestDecodeMatchesTheReferenceDecoder(t *testing.T) {
	for _, c := range referenceVerdicts {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(mustHex(t, c.hex))
			if c.refusal == "" {
				if err != nil {
					t.Errorf("0x%s: %v, but the reference accepts it", c.hex, err)
				}
				return
			}
			want, known := referenceRefusals[c.refusal]
			if !known {
				t.Fatalf("no error for the reference's reason %q", c.refusal)
			}
			if !errors.Is(err, want) {
				t.Errorf("0x%s: %v, but the reference refuses it as %s", c.hex, err, c.refusal)
			}
		})
	}
}
