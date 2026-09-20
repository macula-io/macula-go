package record

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// These tests mirror macula's macula_record_node_geo_tests at merge-11.0.0
// 871986a3 for a node record's coordinates. A coordinate is text as both
// builders write it: an optional leading minus, digits, then optionally a dot
// and digits, in at most 32 bytes, within -90 to 90 for lat and -180 to 180 for
// lng. Any other value, text or not, reads as no coordinate, and NewNodeRecord
// refuses a coordinate that is not a number in its range, by name. Go's float64
// options hold no binary or atom, so the builder's cases of those become NaN
// and the infinities.

func TestAValueThatIsNoCoordinateReadsAsNone(t *testing.T) {
	keys := keysFor(t)
	var values []cbor.Value
	for _, text := range []string{"NaN", "+Inf", "-Inf", "infinity", "abc", "", "-", ".5", "+.5", "-.5", "5.",
		"1e5", "1e+5", "1.5e1", "0x10", "1_000", "1,5", "+1.5", "+4", "--1.0", "1.0.0", "1.5 ", " 1.5", "12abc",
		"1.0e400", "4.9e-324", "１２", strings.Repeat("1", 33), strings.Repeat("1", 1024), "180.5", "-180.000001"} {
		values = append(values, cbor.Text(text))
	}
	values = append(values, cbor.Bytes([]byte("50.8")), cbor.Uint64(12), cbor.Float(1.5), cbor.Map(nil),
		cbor.List([]cbor.Value{cbor.Uint64(1)}))
	for _, value := range values {
		if lat, lng := readGeo(t, keys.node, value, value); lat != nil || lng != nil {
			t.Errorf("%v reads as lat %s and lng %s, want no coordinate", value, showCoordinate(lat), showCoordinate(lng))
		}
	}
}

// The range edges: lat reads within -90 to 90 and lng within -180 to 180, both
// inclusive.
func TestACoordinateReadsOnlyWithinItsRange(t *testing.T) {
	keys := keysFor(t)
	for _, c := range []struct {
		lat, lng         string
		wantLat, wantLng *float64
	}{
		{"90", "180", coordinate(90), coordinate(180)},
		{"-90.0", "-180.0", coordinate(-90), coordinate(-180)},
		{"90.000001", "90.000001", nil, coordinate(90.000001)},
		{"-0", "180.5", coordinate(0), nil},
		{"-90.000001", "-180.5", nil, nil},
	} {
		wantRead(t, keys.node, c.lat, c.lng, c.wantLat, c.wantLng)
	}
}

// Text as both builders write it reads as its number, leading zeros and a
// negative zero included.
func TestACoordinateAsTheBuildersWriteItReads(t *testing.T) {
	keys := keysFor(t)
	for _, c := range []struct {
		lat, lng         string
		wantLat, wantLng *float64
	}{
		{"50.8503", "4", coordinate(50.8503), coordinate(4)},
		{"-0.0", "007", coordinate(math.Copysign(0, -1)), coordinate(7)},
		{"00012.50", "-4", coordinate(12.5), coordinate(-4)},
		{"0.0", "0", coordinate(0), coordinate(0)},
	} {
		wantRead(t, keys.node, c.lat, c.lng, c.wantLat, c.wantLng)
	}
}

// Coordinate text reads only within 32 bytes, however small its number: a
// decimal of 32 bytes reads, and one of 33 does not.
func TestCoordinateTextOver32BytesReadsAsNone(t *testing.T) {
	keys := keysFor(t)
	within := "0." + strings.Repeat("0", 29) + "1"
	over := "0." + strings.Repeat("0", 30) + "1"
	wantRead(t, keys.node, within, over, coordinate(1e-30), nil)
}

// NewNodeRecord refuses, by name, a lat or lng that is not a number within its
// range, a number too large to render included.
func TestNewNodeRecordRefusesACoordinateThatIsNoNumberInRangeByName(t *testing.T) {
	for _, c := range []struct {
		field string
		value float64
	}{
		{"lat", 90.000001}, {"lat", -91}, {"lng", 180.5}, {"lng", -181}, {"lat", 1e300}, {"lng", 1e30},
		{"lat", math.NaN()}, {"lng", math.Inf(1)}, {"lat", math.Inf(-1)},
	} {
		v := c.value
		opts := NodeRecordOptions{Lng: &v}
		if c.field == "lat" {
			opts = NodeRecordOptions{Lat: &v}
		}
		_, err := NewNodeRecord(fill(1), nil, 0, opts)
		if !errors.Is(err, ErrInvalidCoordinate) || !strings.Contains(err.Error(), c.field) {
			t.Errorf("a %s of %v: %v, want %v naming %s", c.field, c.value, err, ErrInvalidCoordinate, c.field)
		}
	}
}

// What the builder writes, at the edges of the range, reads back.
func TestWhatTheBuilderWritesReadsBack(t *testing.T) {
	keys := keysFor(t)
	lat, lng := 90.0, -179.123456
	built := must[Record](t)(NewNodeRecord(keys.node.KeyID(), nil, 0, NodeRecordOptions{Lat: &lat, Lng: &lng}))
	verified := must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(built, keys.node))), profile.PQPure, nowMs())).Record()
	node := must[NodeRecord](t)(ReadNodeRecord(verified))
	if !sameCoordinate(node.Lat, &lat) || !sameCoordinate(node.Lng, &lng) {
		t.Errorf("lat 90 and lng -179.123456 read back as %s and %s", showCoordinate(node.Lat), showCoordinate(node.Lng))
	}
}

// A coordinate renders as OTP 28's float_to_binary/2 renders it with 6
// decimals, compact.
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
	} {
		if got := geoText(c.value); got != c.want {
			t.Errorf("%v renders as %q, want %q", c.value, got, c.want)
		}
	}
}

// readGeo signs a node record whose lat and lng hold the given values,
// verifies it as a peer would, and reads its coordinates back.
func readGeo(t *testing.T, key *identity.NodeKey, lat, lng cbor.Value) (*float64, *float64) {
	t.Helper()
	node := must[Record](t)(NewNodeRecord(key.KeyID(), nil, 0, NodeRecordOptions{}))
	entries, _ := node.Payload.AsMap()
	node.Payload = cbor.Map(withEntry(withEntry(entries, "lat", lat), "lng", lng))
	verified := must[Verified](t)(Verify(wireOf(t, must[Record](t)(Sign(node, key))), profile.PQPure, nowMs())).Record()
	read := must[NodeRecord](t)(ReadNodeRecord(verified))
	return read.Lat, read.Lng
}

// wantRead checks that text lat and lng read back as wantLat and wantLng.
func wantRead(t *testing.T, key *identity.NodeKey, lat, lng string, wantLat, wantLng *float64) {
	t.Helper()
	gotLat, gotLng := readGeo(t, key, cbor.Text(lat), cbor.Text(lng))
	if !sameCoordinate(gotLat, wantLat) || !sameCoordinate(gotLng, wantLng) {
		t.Errorf("lat %q and lng %q read as %s and %s, want %s and %s", lat, lng, showCoordinate(gotLat),
			showCoordinate(gotLng), showCoordinate(wantLat), showCoordinate(wantLng))
	}
}

// sameCoordinate reports whether got reads as want: both none, or the same
// number with the same sign, so -0.0 and 0 differ.
func sameCoordinate(got, want *float64) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return *got == *want && math.Signbit(*got) == math.Signbit(*want)
}

func coordinate(v float64) *float64 { return &v }

func showCoordinate(v *float64) string {
	if v == nil {
		return "none"
	}
	return fmt.Sprint(*v)
}
