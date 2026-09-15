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
// as macula_record has it: a finite coordinate needs far fewer bytes.
const maxGeoTextBytes = 32

// ErrUnreadableCoordinate is a node record's lat or lng that no reader reads
// back: NaN, an infinity, or a number whose text is over 32 bytes.
var ErrUnreadableCoordinate = errors.New("record: a coordinate no reader reads back")

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
// across stacks where float encodings are not. A Lat or Lng that is not
// finite, or whose text is over 32 bytes, is ErrUnreadableCoordinate, since no
// reader reads it back.
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
	}{{"lat", opts.Lat}, {"lng", opts.Lng}} {
		if geo.value == nil {
			continue
		}
		if math.IsNaN(*geo.value) || math.IsInf(*geo.value, 0) {
			return Record{}, fmt.Errorf("%w: %s is %v", ErrUnreadableCoordinate, geo.name, *geo.value)
		}
		text := geoText(*geo.value)
		if len(text) > maxGeoTextBytes {
			return Record{}, fmt.Errorf("%w: %s is %d bytes as text", ErrUnreadableCoordinate, geo.name, len(text))
		}
		entries = append(entries, textEntry(geo.name, text))
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
		Lat:          parseGeo(text("lat")),
		Lng:          parseGeo(text("lng")),
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

// parseGeo reads a coordinate's text as macula_record's parse_geo/1 does at
// merge-11.0.0 24c5e619: text of at most 32 bytes that string:to_float/1, or
// else string:to_integer/1, reads in full. Any other text is nil.
func parseGeo(s string) *float64 {
	if len(s) > maxGeoTextBytes {
		return nil
	}
	if v, ok := geoFloat(s); ok {
		return &v
	}
	if v, ok := geoInteger(s); ok {
		return &v
	}
	return nil
}

// geoFloat reads s as string:to_float/1 reads a whole text: an optional sign,
// ASCII digits, a point or a comma, digits, and an optional exponent of e or E,
// an optional sign and digits. It reads when the number is finite, so an
// underflow reads as 0 and an overflow does not read.
func geoFloat(s string) (float64, bool) {
	mantissa := withoutSign(s)
	whole := leadingDigits(mantissa)
	if whole == 0 || whole == len(mantissa) || (mantissa[whole] != '.' && mantissa[whole] != ',') {
		return 0, false
	}
	rest := mantissa[whole+1:]
	fraction := leadingDigits(rest)
	if fraction == 0 {
		return 0, false
	}
	if exponent := rest[fraction:]; exponent != "" {
		if exponent[0] != 'e' && exponent[0] != 'E' {
			return 0, false
		}
		if digits := withoutSign(exponent[1:]); digits == "" || leadingDigits(digits) != len(digits) {
			return 0, false
		}
	}
	v, err := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64)
	if math.IsInf(v, 0) || (err != nil && !errors.Is(err, strconv.ErrRange)) {
		return 0, false
	}
	return v, true
}

// geoInteger reads s as string:to_integer/1 reads a whole text, an optional
// sign and ASCII digits, as the nearest float64, with an integer zero as 0.
// At most 32 digits never overflow a float64.
func geoInteger(s string) (float64, bool) {
	digits := withoutSign(s)
	if digits == "" || leadingDigits(digits) != len(digits) {
		return 0, false
	}
	v, err := strconv.ParseFloat(digits, 64)
	if err != nil {
		return 0, false
	}
	if s[0] == '-' && v != 0 {
		v = -v
	}
	return v, true
}

// withoutSign is s without one leading + or -.
func withoutSign(s string) string {
	if s != "" && (s[0] == '+' || s[0] == '-') {
		return s[1:]
	}
	return s
}

// leadingDigits is how many ASCII digits s starts with.
func leadingDigits(s string) int {
	n := 0
	for n < len(s) && s[n] >= '0' && s[n] <= '9' {
		n++
	}
	return n
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
