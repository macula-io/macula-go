package record

import (
	"math"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_node_geo_tests at merge-11.0.0
// 24c5e619 for a node record's coordinates: text that does not spell a finite
// float or integer of at most 32 bytes, and a value that is not text, reads as
// no coordinate, and a finite value still reads. The tables beside them hold
// what OTP 28 reads and renders: string:to_float/1, then string:to_integer/1,
// under parse_geo/1's rule, and float_to_binary/2 with 6 decimals, compact.

func TestACoordinateThatIsNoFiniteNumberReadsAsNone(t *testing.T) {
	keys := keysFor(t)
	for _, c := range []struct {
		name  string
		value cbor.Value
	}{
		{"NaN", cbor.Text("NaN")},
		{"+Inf", cbor.Text("+Inf")},
		{"-Inf", cbor.Text("-Inf")},
		{"abc", cbor.Text("abc")},
		{"empty text", cbor.Text("")},
		{"1024 ones", cbor.Text(strings.Repeat("1", 1024))},
		{"12abc", cbor.Text("12abc")},
		{"1.5 and a space", cbor.Text("1.5 ")},
		{"1e400", cbor.Text("1e400")},
		{"an integer", cbor.Uint64(12)},
		{"a map", cbor.Map(nil)},
		{"a list", cbor.List([]cbor.Value{cbor.Uint64(1)})},
	} {
		if lat, lng := readGeo(t, keys.node, c.value, c.value); lat != nil || lng != nil {
			t.Errorf("%s reads as lat %v and lng %v, want no coordinate", c.name, lat, lng)
		}
	}
}

func TestAFiniteCoordinateStillReads(t *testing.T) {
	keys := keysFor(t)
	lat, lng := readGeo(t, keys.node, cbor.Text("50.8503"), cbor.Text("4"))
	if lat == nil || *lat != 50.8503 || lng == nil || *lng != 4 {
		t.Errorf("50.8503 and 4 read as lat %v and lng %v", lat, lng)
	}
}

// readGeo signs a node record whose lat and lng hold the given values,
// verifies it as a peer would, and reads its coordinates back.
func readGeo(t *testing.T, key *identity.NodeKey, lat, lng cbor.Value) (*float64, *float64) {
	t.Helper()
	node := must[Record](t)(NewNodeRecord(key.KeyID(), nil, 0, NodeRecordOptions{}))
	entries, _ := node.Payload.AsMap()
	node.Payload = cbor.Map(withEntry(withEntry(entries, "lat", lat), "lng", lng))
	verified := must[Record](t)(Verify(wireOf(t, must[Record](t)(Sign(node, key))), profile.PQPure, nowMs()))
	read := must[NodeRecord](t)(ReadNodeRecord(verified))
	return read.Lat, read.Lng
}

// Coordinate text reads as OTP 28 reads it under parse_geo/1's rule, nil for no
// coordinate: a point or a comma before the fraction, digits on both sides of
// it, an exponent only after a fraction, an underflow as 0, and no more than 32
// bytes.
func TestCoordinateTextReadsAsOTPReadsIt(t *testing.T) {
	number := func(v float64) *float64 { return &v }
	negativeZero := math.Copysign(0, -1)
	for _, c := range []struct {
		text string
		want *float64
	}{
		{"50.8", number(50.8)},
		{"50.8503", number(50.8503)},
		{"4", number(4)},
		{"4.0", number(4)},
		{"-4.0", number(-4)},
		{"+4.0", number(4)},
		{"+4", number(4)},
		{"-4", number(-4)},
		{"-0", number(0)},
		{"0.0", number(0)},
		{"-0.0", &negativeZero},
		{"1e5", nil},
		{"1.0e5", number(1e5)},
		{"1.0E5", number(1e5)},
		{"1.0e+5", number(1e5)},
		{"1.0e-5", number(1e-5)},
		{"1e+5", nil},
		{"1.5e", nil},
		{"1.5e+", nil},
		{".5", nil},
		{"+.5", nil},
		{"5.", nil},
		{"1.5 ", nil},
		{" 1.5", nil},
		{"\t1.5", nil},
		{"1.5\n", nil},
		{"12abc", nil},
		{"abc", nil},
		{"1e400", nil},
		{"1.0e400", nil},
		{"1.0e308", number(1e308)},
		{"1.0e-400", number(0)},
		{"4.9e-324", number(5e-324)},
		{"NaN", nil},
		{"nan", nil},
		{"Inf", nil},
		{"+Inf", nil},
		{"-Inf", nil},
		{"infinity", nil},
		{"", nil},
		{"0x10", nil},
		{"1_000", nil},
		{"--1.0", nil},
		{"1.0.0", nil},
		{"1.5e5.0", nil},
		{"00012.50", number(12.5)},
		{"007", number(7)},
		{"1,5", number(1.5)},
		{"-", nil},
		{"+", nil},
		{"12345678901234567890123456789012", number(12345678901234567890123456789012)},
		{"123456789012345678901234567890123", nil},
		{"1.000000000000000000000000000000", number(1)},
		{"1.0000000000000000000000000000000", nil},
		{"-1234567890123456789012345.123456", nil},
		{"１.５", nil},
		{"\xff", nil},
		{"1.5\xff", nil},
		{"1,0e5", number(1e5)},
		{"1,5E-2", number(0.015)},
		{",5", nil},
		{"5,", nil},
		{"1,2,3", nil},
		{"1.2,3", nil},
		{"-1,5", number(-1.5)},
		{"+1.5", number(1.5)},
		{"1.5e-400", number(0)},
		{"1.0e05", number(1e5)},
		{"1.0e+", nil},
		{"1.0e-0", number(1)},
		{"1.5e1.0", nil},
		{"0.5e", nil},
		{"1.0ee5", nil},
		{"1.0e309", nil},
		{"-1.0e309", nil},
		{"1.7976931348623157e308", number(math.MaxFloat64)},
		{"-2.5E-3", number(-0.0025)},
		{"9.", nil},
		{"-.", nil},
	} {
		got := parseGeo(c.text)
		switch {
		case c.want == nil && got != nil:
			t.Errorf("%q reads as %v, want no coordinate", c.text, *got)
		case c.want != nil && got == nil:
			t.Errorf("%q reads as no coordinate, want %v", c.text, *c.want)
		case c.want != nil && (*got != *c.want || math.Signbit(*got) != math.Signbit(*c.want)):
			t.Errorf("%q reads as %v, want %v", c.text, *got, *c.want)
		}
	}
}

// A coordinate renders as OTP 28's float_to_binary/2 renders it with 6
// decimals, compact, and reads back as the number that text spells.
func TestACoordinateRendersAsMaculaRendersIt(t *testing.T) {
	for _, c := range []struct {
		value float64
		want  string
	}{
		{50.8, "50.8"},
		{50.8503, "50.8503"},
		{4, "4.0"},
		{math.Copysign(0, -1), "-0.0"},
		{1e-7, "0.0"},
		{123.4567894, "123.456789"},
		{179.9999995, "180.0"},
		{1e20, "100000000000000000000.0"},
		{1e24, "999999999999999983222784.0"},
		{1e25, "10000000000000000905969664.0"},
	} {
		got := geoText(c.value)
		if got != c.want {
			t.Errorf("%v renders as %q, want %q", c.value, got, c.want)
		}
		if parseGeo(got) == nil {
			t.Errorf("%v renders as %q, which does not read back", c.value, got)
		}
	}
}

// NewNodeRecord refuses a lat or lng that no reader reads back: NaN, an
// infinity, or a number whose text is over 32 bytes, as 1e30 is at 33.
func TestNewNodeRecordRefusesACoordinateNoReaderReadsBack(t *testing.T) {
	for _, c := range []struct {
		name  string
		value float64
	}{
		{"NaN", math.NaN()},
		{"+Inf", math.Inf(1)},
		{"-Inf", math.Inf(-1)},
		{"1e30", 1e30},
		{"-1e300", -1e300},
	} {
		v := c.value
		_, err := NewNodeRecord(fill(1), nil, 0, NodeRecordOptions{Lat: &v})
		wantRefusal(t, "a lat of "+c.name, err, ErrUnreadableCoordinate)
		_, err = NewNodeRecord(fill(1), nil, 0, NodeRecordOptions{Lng: &v})
		wantRefusal(t, "a lng of "+c.name, err, ErrUnreadableCoordinate)
	}
}
