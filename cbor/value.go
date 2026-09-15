// Package cbor implements Macula's wire encoding, the codec of macula's
// macula_record_cbor: deterministic CBOR on the way out, and macula's
// post-quantum decoding rule on the way in.
//
// Encode writes what a signer must: integers and lengths in their shortest
// form, map keys sorted by the bytewise order of their own encoded bytes, and
// floats always as binary64, never the shortest width that round-trips.
// Signatures and content ids are computed over these exact bytes, so a
// generic canonical CBOR library, which follows RFC 8949's own rules instead,
// produces bytes that do not match.
//
// Decode accepts exactly what every stack accepts from a peer. It refuses
// bytes after the top-level value, indefinite lengths, tags, simple values
// other than null, text that is not valid UTF-8, map keys other than text or
// integers, duplicate map keys, nesting deeper than 64 levels, integers
// outside -2^63 to 2^63-1, and floats that are NaN or infinite. It accepts
// lengths in any width, map keys in any order, and half, single and double
// floats.
//
// No external CBOR library is used, on purpose: the bytes this package
// writes and the inputs it refuses are part of the protocol.
package cbor

import "fmt"

// Kind identifies which of the eight wire-representable shapes a Value
// holds. There is no bool, no CBOR tag (major 6), and no "undefined"
// simple value — none of those exist in the live protocol.
type Kind int

const (
	KindUInt Kind = iota
	KindNegInt
	KindBytes
	KindText
	KindList
	KindMap
	KindNull
	KindFloat
)

// MapEntry is one key/value pair of a Value of KindMap. Insertion order
// on construction; Encode sorts by encoded-key-bytes, it does not
// require the caller to pre-sort.
type MapEntry struct {
	Key Value
	Val Value
}

// Value is Macula's wire value model — mirrors deterministic.rs's own
// Value enum exactly (UInt/NegInt/Bytes/Text/List/Map/Null/Float).
type Value struct {
	kind   Kind
	uintV  uint64 // KindUInt: the value. KindNegInt: wire magnitude N (actual = -1-N).
	bytesV []byte
	textV  string
	listV  []Value
	mapV   []MapEntry
	floatV float64
}

func (v Value) Kind() Kind { return v.kind }

// Int builds the Value for a signed integer in [-(2^64), math.MaxUint64].
// A plain Go int64 covers only part of that range; use Uint64 directly
// for the top half of the positive range.
func Int(i int64) Value {
	if i >= 0 {
		return Value{kind: KindUInt, uintV: uint64(i)}
	}
	// actual = -1 - N  =>  N = -1 - actual = -(actual+1)
	// i is negative here, so -(i+1) is safe from int64 overflow except
	// at i == math.MinInt64, where i+1 still fits (MinInt64+1).
	n := uint64(-(i + 1))
	return Value{kind: KindNegInt, uintV: n}
}

// Uint64 builds the Value for a non-negative integer up to math.MaxUint64.
func Uint64(u uint64) Value { return Value{kind: KindUInt, uintV: u} }

// NegInt builds the Value for the wire's own negative representation
// directly: actual value = -1 - magnitude. Reaches values Int cannot
// (down to -(2^64)) when magnitude is math.MaxUint64.
func NegInt(magnitude uint64) Value { return Value{kind: KindNegInt, uintV: magnitude} }

func Bytes(b []byte) Value { return Value{kind: KindBytes, bytesV: b} }
func Text(s string) Value  { return Value{kind: KindText, textV: s} }
func List(vs []Value) Value {
	return Value{kind: KindList, listV: vs}
}
func Map(entries []MapEntry) Value { return Value{kind: KindMap, mapV: entries} }
func Null() Value                  { return Value{kind: KindNull} }
func Float(f float64) Value        { return Value{kind: KindFloat, floatV: f} }

// AsInt64 returns the value as an int64 along with whether it fit
// (KindUInt > math.MaxInt64, or KindNegInt below math.MinInt64, do not).
func (v Value) AsInt64() (int64, bool) {
	switch v.kind {
	case KindUInt:
		if v.uintV > (1<<63)-1 {
			return 0, false
		}
		return int64(v.uintV), true
	case KindNegInt:
		if v.uintV >= 1<<63 {
			return 0, false
		}
		return -1 - int64(v.uintV), true
	default:
		return 0, false
	}
}

func (v Value) AsBytes() ([]byte, bool) {
	if v.kind != KindBytes {
		return nil, false
	}
	return v.bytesV, true
}

func (v Value) AsText() (string, bool) {
	if v.kind != KindText {
		return "", false
	}
	return v.textV, true
}

func (v Value) AsList() ([]Value, bool) {
	if v.kind != KindList {
		return nil, false
	}
	return v.listV, true
}

func (v Value) AsMap() ([]MapEntry, bool) {
	if v.kind != KindMap {
		return nil, false
	}
	return v.mapV, true
}

func (v Value) IsNull() bool { return v.kind == KindNull }

func (v Value) AsFloat() (float64, bool) {
	if v.kind != KindFloat {
		return 0, false
	}
	return v.floatV, true
}

// Get looks up a text-keyed entry in a KindMap value — the common case,
// since every wire map's keys are frame/field names (§4's atom→text
// mapping). Returns (Value{}, false) if v isn't a map or the key isn't
// present.
func (v Value) Get(key string) (Value, bool) {
	entries, ok := v.AsMap()
	if !ok {
		return Value{}, false
	}
	for _, e := range entries {
		if t, ok := e.Key.AsText(); ok && t == key {
			return e.Val, true
		}
	}
	return Value{}, false
}

func (v Value) String() string {
	switch v.kind {
	case KindUInt:
		return fmt.Sprintf("%d", v.uintV)
	case KindNegInt:
		return negativeText(v.uintV)
	case KindBytes:
		return fmt.Sprintf("bytes(%d)", len(v.bytesV))
	case KindText:
		return fmt.Sprintf("%q", v.textV)
	case KindList:
		return fmt.Sprintf("list(%d)", len(v.listV))
	case KindMap:
		return fmt.Sprintf("map(%d)", len(v.mapV))
	case KindNull:
		return "null"
	case KindFloat:
		return fmt.Sprintf("%g", v.floatV)
	default:
		return "?"
	}
}
