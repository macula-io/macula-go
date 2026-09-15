package record

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"

	"github.com/macula-io/macula-go/cbor"
)

// maxGeoTextBytes is the longest coordinate text a node record's reader reads,
// as macula_record has it: a coordinate needs far fewer bytes.
const maxGeoTextBytes = 32

// How far from zero a latitude and a longitude reach, both inclusive.
const (
	latBound = 90
	lngBound = 180
)

// ErrInvalidCoordinate is a node record's lat or lng that is not a number
// within its range: -90 to 90 for lat, -180 to 180 for lng.
var ErrInvalidCoordinate = errors.New("record: a coordinate that is not a number within its range")

// NodeRecordOptions are a node record's optional fields, as macula_record's
// node_record/4 takes them. StationID is nil for the node itself. Text fields
// left empty, and Lat and Lng left nil, are left out. Kind is "station" for a
// relay identity and "daemon" for a client identity. Peers are the node_ids of
// the stations this node holds an overlay session with, kept sorted and once
// each. TTLMs is 0 for the default, 48 hours.
type NodeRecordOptions struct {
	StationID   *[32]byte
	CapsHint    string
	DisplayName string
	Hostname    string
	Endpoint    string
	City        string
	Country     string
	Lat         *float64
	Lng         *float64
	Kind        string
	Peers       [][32]byte
	TTLMs       uint64
}

// NewNodeRecord is an unsigned node record about nodeID, which signs it, with
// the realms it serves and its capabilities. Coordinates travel as text, with
// at most 6 decimals and no trailing zeros, since a fixed rendering is stable
// across stacks where float encodings are not. A Lat outside -90 to 90, a Lng
// outside -180 to 180, or either of them NaN, is ErrInvalidCoordinate, naming
// the field, so the builder writes only text a reader takes.
func NewNodeRecord(nodeID [32]byte, realms [][32]byte, capabilities uint64, opts NodeRecordOptions) (Record, error) {
	stationID := nodeID
	if opts.StationID != nil {
		stationID = *opts.StationID
	}
	entries := []cbor.MapEntry{
		bytesEntry("node_id", bytes.Clone(nodeID[:])),
		bytesEntry("station_id", bytes.Clone(stationID[:])),
		valueEntry("realms", idList(realms)),
		uintEntry("capabilities", capabilities),
	}
	for _, text := range []struct{ name, value string }{
		{"caps_hint", opts.CapsHint}, {"display_name", opts.DisplayName}, {"hostname", opts.Hostname},
		{"endpoint", opts.Endpoint}, {"city", opts.City}, {"country", opts.Country}, {"kind", opts.Kind},
	} {
		if text.value != "" {
			entries = append(entries, textEntry(text.name, text.value))
		}
	}
	for _, geo := range []struct {
		name  string
		value *float64
		bound float64
	}{{"lat", opts.Lat, latBound}, {"lng", opts.Lng, lngBound}} {
		if geo.value == nil {
			continue
		}
		if !(math.Abs(*geo.value) <= geo.bound) {
			return Record{}, fmt.Errorf("%w: %s %v", ErrInvalidCoordinate, geo.name, *geo.value)
		}
		entries = append(entries, textEntry(geo.name, geoText(*geo.value)))
	}
	if peers := sortedIDs(opts.Peers); len(peers) > 0 {
		entries = append(entries, valueEntry("peers", idList(peers)))
	}
	return unsigned(TypeNodeRecord, cbor.Map(entries), opts.TTLMs)
}

// NodeRecord is a node record's payload, as macula_record's read_node_record/1
// reads it. A field the payload leaves out, or carries as another kind, is zero
// or nil, and so are Lat and Lng unless their text reads as a coordinate.
// Version is the build a station stamps on its re-announced record.
type NodeRecord struct {
	NodeID       [32]byte
	StationID    [32]byte
	Realms       [][32]byte
	Capabilities uint64
	Kind         string
	Hostname     string
	Endpoint     string
	City         string
	Country      string
	Lat          *float64
	Lng          *float64
	DisplayName  string
	CapsHint     string
	Peers        [][32]byte
	Version      string
}

// ReadNodeRecord reads a node record's payload. A record of another type is
// ErrMalformed.
func ReadNodeRecord(r Record) (NodeRecord, error) {
	if r.Type != TypeNodeRecord {
		return NodeRecord{}, fmt.Errorf("%w: a record of type %#02x is not a node record", ErrMalformed, uint8(r.Type))
	}
	text := func(name string) string {
		value, _ := r.Payload.Get(name)
		s, _ := value.AsText()
		return s
	}
	capabilities, _ := payloadField(r.Payload, "capabilities").AsInt64()
	node := NodeRecord{
		Realms:       readIDs(payloadField(r.Payload, "realms")),
		Capabilities: uint64(max(capabilities, 0)),
		Kind:         text("kind"),
		Hostname:     text("hostname"),
		Endpoint:     text("endpoint"),
		City:         text("city"),
		Country:      text("country"),
		Lat:          parseGeo(text("lat"), latBound),
		Lng:          parseGeo(text("lng"), lngBound),
		DisplayName:  text("display_name"),
		CapsHint:     text("caps_hint"),
		Peers:        readIDs(payloadField(r.Payload, "peers")),
		Version:      text("version"),
	}
	readID(node.NodeID[:], payloadField(r.Payload, "node_id"))
	readID(node.StationID[:], payloadField(r.Payload, "station_id"))
	return node, nil
}

// geoText is a coordinate as macula renders one, float_to_binary with 6
// decimals, compact: trailing zeros cut, keeping one digit after the point.
func geoText(v float64) string {
	s := strings.TrimRight(strconv.FormatFloat(v, 'f', 6, 64), "0")
	if strings.HasSuffix(s, ".") {
		s += "0"
	}
	return s
}

// parseGeo reads a coordinate's text as macula_record's parse_geo/2 does at
// merge-11.0.0 871986a3: text as both builders write it, of at most 32 bytes,
// an optional leading minus, digits, then optionally a dot and digits, within
// bound of zero either way. An integer zero reads as 0, since it has no sign.
// Any other text is nil, and so is a value that is not text, which reads as
// empty text.
func parseGeo(s string, bound float64) *float64 {
	if len(s) > maxGeoTextBytes || !geoShaped(s) {
		return nil
	}
	// Text of this shape and length always parses to a finite float64.
	v, _ := strconv.ParseFloat(s, 64)
	if math.Abs(v) > bound {
		return nil
	}
	if v == 0 && !strings.Contains(s, ".") {
		v = 0
	}
	return &v
}

// geoShaped reports whether s is an optional leading minus, one or more ASCII
// digits, then optionally a dot and one or more digits.
func geoShaped(s string) bool {
	whole, fraction, hasDot := strings.Cut(strings.TrimPrefix(s, "-"), ".")
	return allDigits(whole) && (!hasDot || allDigits(fraction))
}

// allDigits reports whether s is one or more ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// sortedIDs is ids sorted, once each.
func sortedIDs(ids [][32]byte) [][32]byte {
	sorted := slices.Clone(ids)
	slices.SortFunc(sorted, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return slices.Compact(sorted)
}

func idList(ids [][32]byte) cbor.Value {
	values := make([]cbor.Value, len(ids))
	for i, id := range ids {
		values[i] = cbor.Bytes(bytes.Clone(id[:]))
	}
	return cbor.List(values)
}

// readIDs reads the 32-byte ids of a list, leaving out anything else.
func readIDs(v cbor.Value) [][32]byte {
	items, _ := v.AsList()
	var ids [][32]byte
	for _, item := range items {
		var id [32]byte
		if readID(id[:], item) {
			ids = append(ids, id)
		}
	}
	return ids
}

// readID copies a 32-byte id into dst, and reports whether v was one.
func readID(dst []byte, v cbor.Value) bool {
	b, isBytes := v.AsBytes()
	if !isBytes || len(b) != 32 {
		return false
	}
	copy(dst, b)
	return true
}

func payloadField(payload cbor.Value, name string) cbor.Value {
	value, _ := payload.Get(name)
	return value
}
