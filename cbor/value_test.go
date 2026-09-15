package cbor

import (
	"math"
	"testing"
)

// AsInt64 reports a value as fitting exactly when it lies from -2^63 to 2^63-1,
// the range the decoding rule accepts, and returns it unchanged.
func TestAsInt64FitsExactlyTheInt64Range(t *testing.T) {
	cases := []struct {
		name string
		v    Value
		want int64
		fits bool
	}{
		{"2^63-1", Uint64(math.MaxInt64), math.MaxInt64, true},
		{"2^63", Uint64(1 << 63), 0, false},
		{"-1", NegInt(0), -1, true},
		{"-2^63", NegInt(math.MaxInt64), math.MinInt64, true},
		{"-2^63-1", NegInt(1 << 63), 0, false},
		{"-2^64", NegInt(math.MaxUint64), 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, fits := c.v.AsInt64()
			if fits != c.fits || (fits && got != c.want) {
				t.Errorf("AsInt64() = (%d, %v), want (%d, %v)", got, fits, c.want, c.fits)
			}
		})
	}
}

// String prints every integer a Value can hold, the negative ones beyond
// int64's range included.
func TestStringPrintsEveryIntegerAValueCanHold(t *testing.T) {
	cases := []struct {
		v    Value
		want string
	}{
		{Uint64(math.MaxUint64), "18446744073709551615"},
		{NegInt(0), "-1"},
		{NegInt(math.MaxInt64), "-9223372036854775808"},
		{NegInt(1 << 63), "-9223372036854775809"},
		{NegInt(math.MaxUint64), "-18446744073709551616"},
	}
	for _, c := range cases {
		if got := c.v.String(); got != c.want {
			t.Errorf("String() = %s, want %s", got, c.want)
		}
	}
}
