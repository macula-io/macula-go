package cbor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// MaxNestingDepth is how many arrays and maps may nest inside each other,
// the outermost counted: 64 levels decode, and a 65th is refused, as in
// macula's decoding rule.
const MaxNestingDepth = 64

// MaxElements is how many CBOR items one Decode may read: every item counts
// once, the top-level value, array elements, map keys and map values included.
// It is macula's element budget, so an input macula refuses for the items it
// holds is refused here too.
const MaxElements = 131072

// The refusals of the decoding rule, one for each reason macula's reference
// decoder gives, so an input is refused for the same reason in every stack.
var (
	// ErrTrailingBytes is input with bytes after its top-level value.
	ErrTrailingBytes = errors.New("cbor: decode: bytes after the top-level value")
	// ErrBadKey is a map key that is neither text nor an integer.
	ErrBadKey = errors.New("cbor: decode: a map key that is neither text nor an integer")
	// ErrDuplicateKey is a map key equal to an earlier key of its map: text
	// with the same bytes, or an integer of the same value, in any width.
	ErrDuplicateKey = errors.New("cbor: decode: a duplicate map key")
	// ErrInvalidText is text that is not valid UTF-8.
	ErrInvalidText = errors.New("cbor: decode: text that is not valid UTF-8")
	// ErrNestingTooDeep is arrays and maps nested more than MaxNestingDepth
	// levels.
	ErrNestingTooDeep = errors.New("cbor: decode: arrays and maps nested more than 64 levels")
	// ErrIntegerOutOfRange is an integer below -2^63 or above 2^63-1.
	ErrIntegerOutOfRange = errors.New("cbor: decode: an integer below -2^63 or above 2^63-1")
	// ErrTooManyElements is input that holds more than MaxElements items.
	ErrTooManyElements = errors.New("cbor: decode: more than 131072 items")
	// ErrMalformed is input that is not one complete item of what the rule
	// allows: truncated input, an indefinite length, a tag, a simple value
	// other than null, or a float that is NaN or infinite.
	ErrMalformed = errors.New("cbor: decode: malformed")
)

// Decode parses data as exactly one value under macula's post-quantum decoding
// rule, the rule every stack applies to what a peer sends. It accepts lengths
// in any width, map keys in any order, and half, single and double floats, and
// refuses with an error wrapping one of the refusals above. Every path returns
// an error rather than panicking, since the input is untrusted.
func Decode(data []byte) (Value, error) {
	d := decoder{data: data, budget: MaxElements}
	v, err := d.item(0)
	if err != nil {
		return Value{}, err
	}
	if d.pos != len(data) {
		return Value{}, ErrTrailingBytes
	}
	return v, nil
}

// decoder reads one value from data: pos is how far it has read, and budget
// how many more items it may read.
type decoder struct {
	data   []byte
	pos    int
	budget int
}

// item decodes the item at pos, which sits inside depth arrays and maps. As in
// macula's decoder, an item is counted against the budget once its head and
// argument have been read, and before its own checks.
func (d *decoder) item(depth int) (Value, error) {
	head, err := d.take(1)
	if err != nil {
		return Value{}, err
	}
	major, ai := head[0]>>5, head[0]&0x1F
	if major == majorFloat {
		return d.simpleOrFloat(ai)
	}
	arg, err := d.argument(ai)
	if err != nil {
		return Value{}, err
	}
	if err := d.count(); err != nil {
		return Value{}, err
	}
	switch major {
	case majorUInt:
		return integer(Uint64(arg), arg)
	case majorNegInt:
		return integer(NegInt(arg), arg)
	case majorBytes:
		return d.byteString(arg)
	case majorText:
		return d.text(arg)
	case majorList:
		return d.list(arg, depth)
	case majorMap:
		return d.mapOf(arg, depth)
	default:
		return Value{}, fmt.Errorf("%w: a tag", ErrMalformed)
	}
}

// count takes one item from the budget.
func (d *decoder) count() error {
	if d.budget == 0 {
		return ErrTooManyElements
	}
	d.budget--
	return nil
}

// take is the next n bytes of the input, and moves past them.
func (d *decoder) take(n uint64) ([]byte, error) {
	remaining := len(d.data) - d.pos
	if n > uint64(remaining) {
		return nil, fmt.Errorf("%w: %d bytes needed, %d left", ErrMalformed, n, remaining)
	}
	b := d.data[d.pos : d.pos+int(n)]
	d.pos += int(n)
	return b, nil
}

// argumentWidths is how many bytes follow a head for each additional
// information that points past it.
var argumentWidths = map[byte]uint64{ai1: 1, ai2: 2, ai4: 4, ai8: 8}

// argument is a head's argument, a value or a length: its additional
// information itself up to 23, or the 1, 2, 4 or 8 bytes after the head, in
// whichever width the sender chose. Additional information 28 to 31, every
// indefinite length among them, is malformed.
func (d *decoder) argument(ai byte) (uint64, error) {
	if ai <= maxInAI {
		return uint64(ai), nil
	}
	width, ok := argumentWidths[ai]
	if !ok {
		return 0, fmt.Errorf("%w: additional information %d", ErrMalformed, ai)
	}
	b, err := d.take(width)
	if err != nil {
		return 0, err
	}
	var arg uint64
	for _, x := range b {
		arg = arg<<8 | uint64(x)
	}
	return arg, nil
}

// integer is an integer head's value, refused when its argument puts it
// outside -2^63 to 2^63-1: an unsigned argument of 2^63 or more is above
// 2^63-1, and a negative one of 2^63 or more is below -2^63.
func integer(v Value, arg uint64) (Value, error) {
	if arg >= 1<<63 {
		return Value{}, ErrIntegerOutOfRange
	}
	return v, nil
}

// byteString is the next n bytes, copied out of the input.
func (d *decoder) byteString(n uint64) (Value, error) {
	b, err := d.take(n)
	if err != nil {
		return Value{}, err
	}
	out := make([]byte, len(b))
	copy(out, b)
	return Bytes(out), nil
}

// text is the next n bytes as text, which must be valid UTF-8.
func (d *decoder) text(n uint64) (Value, error) {
	b, err := d.take(n)
	if err != nil {
		return Value{}, err
	}
	if !utf8.Valid(b) {
		return Value{}, ErrInvalidText
	}
	return Text(string(b)), nil
}

// floatWidths is how many bytes follow the head of a half, a single and a
// double float.
var floatWidths = map[byte]uint64{ai2: 2, ai4: 4, ai8: 8}

// simpleOrFloat decodes major type 7, counting the item once its bytes have
// been read: null, or a finite half, single or double float. Every other
// simple value, a boolean among them, is malformed, and so is a float that is
// NaN or infinite.
func (d *decoder) simpleOrFloat(ai byte) (Value, error) {
	width, isFloat := floatWidths[ai]
	switch {
	case ai == aiNull:
		if err := d.count(); err != nil {
			return Value{}, err
		}
		return Null(), nil
	case isFloat:
		return d.float(width)
	case ai <= ai1:
		if _, err := d.argument(ai); err != nil {
			return Value{}, err
		}
		if err := d.count(); err != nil {
			return Value{}, err
		}
		return Value{}, fmt.Errorf("%w: simple value with additional information %d", ErrMalformed, ai)
	default:
		return Value{}, fmt.Errorf("%w: additional information %d", ErrMalformed, ai)
	}
}

// float is the float in the next width bytes, which must be finite.
func (d *decoder) float(width uint64) (Value, error) {
	b, err := d.take(width)
	if err != nil {
		return Value{}, err
	}
	if err := d.count(); err != nil {
		return Value{}, err
	}
	f := floatFrom(b)
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return Value{}, fmt.Errorf("%w: a float that is NaN or infinite", ErrMalformed)
	}
	return Float(f), nil
}

// floatFrom is the float in b: a half, a single or a double by its length.
func floatFrom(b []byte) float64 {
	switch len(b) {
	case 2:
		return float16ToFloat64(binary.BigEndian.Uint16(b))
	case 4:
		return float64(math.Float32frombits(binary.BigEndian.Uint32(b)))
	default:
		return math.Float64frombits(binary.BigEndian.Uint64(b))
	}
}

// list decodes an array of count items that sits inside depth arrays and maps.
func (d *decoder) list(count uint64, depth int) (Value, error) {
	if depth >= MaxNestingDepth {
		return Value{}, ErrNestingTooDeep
	}
	items := make([]Value, 0, d.sizeHint(count, 1))
	for i := uint64(0); i < count; i++ {
		item, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		items = append(items, item)
	}
	return List(items), nil
}

// mapKey is what makes two map keys the same key: the kind, and the text or
// the integer argument.
type mapKey struct {
	kind Kind
	text string
	arg  uint64
}

// keyOf is a map key's identity, and whether the key is text or an integer,
// the only kinds the rule admits.
func keyOf(k Value) (mapKey, bool) {
	switch k.kind {
	case KindText:
		return mapKey{kind: KindText, text: k.textV}, true
	case KindUInt, KindNegInt:
		return mapKey{kind: k.kind, arg: k.uintV}, true
	default:
		return mapKey{}, false
	}
}

// mapOf decodes a map of count entries that sits inside depth arrays and maps.
// Each entry's value decodes before its key is judged, as in the reference
// decoder, so an input that breaks two checks is refused for the same one in
// every stack. Duplicates are found through a Go map, so the work grows with
// the number of keys, not with its square.
func (d *decoder) mapOf(count uint64, depth int) (Value, error) {
	if depth >= MaxNestingDepth {
		return Value{}, ErrNestingTooDeep
	}
	entries := make([]MapEntry, 0, d.sizeHint(count, 2))
	seen := make(map[mapKey]struct{}, d.sizeHint(count, 2))
	for i := uint64(0); i < count; i++ {
		key, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		val, err := d.item(depth + 1)
		if err != nil {
			return Value{}, err
		}
		id, admitted := keyOf(key)
		if !admitted {
			return Value{}, ErrBadKey
		}
		if _, duplicate := seen[id]; duplicate {
			return Value{}, ErrDuplicateKey
		}
		seen[id] = struct{}{}
		entries = append(entries, MapEntry{Key: key, Val: val})
	}
	return Map(entries), nil
}

// maxSizeHint bounds the room a list or map is given before its elements
// decode.
const maxSizeHint = 4

// sizeHint is the room to give a list or map that declares count elements of
// at least itemsPerElement items and bytes each. A declared count is not
// checked against the input, so it is never trusted as an allocation size: the
// room is at most the count, what the bytes left and the budget left could
// hold, and maxSizeHint. A list or map then grows as its elements actually
// decode, so what decoding allocates follows the bytes present, not the counts
// they declare.
func (d *decoder) sizeHint(count uint64, itemsPerElement int) int {
	bytesLeft := uint64((len(d.data) - d.pos) / itemsPerElement)
	budgetLeft := uint64(d.budget / itemsPerElement)
	return int(min(count, bytesLeft, budgetLeft, maxSizeHint))
}

// float16ToFloat64 converts an IEEE 754 binary16 value to float64.
// Decode-only path (see the package doc: this protocol never encodes
// float16, only accepts it for interop), hand-rolled to avoid a
// dependency for one conversion.
func float16ToFloat64(bits uint16) float64 {
	sign := uint64(bits>>15) & 0x1
	exp := uint64(bits>>10) & 0x1F
	frac := uint64(bits) & 0x3FF

	switch exp {
	case 0:
		if frac == 0 {
			return math.Float64frombits(sign << 63)
		}
		// Subnormal: value = frac/1024 * 2^-14.
		return math.Ldexp(float64(frac), -24) * signMul(sign)
	case 0x1F:
		if frac == 0 {
			if sign == 1 {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		return math.NaN()
	default:
		// Normal: value = (1 + frac/1024) * 2^(exp-15).
		return math.Ldexp(1+float64(frac)/1024, int(exp)-15) * signMul(sign)
	}
}

func signMul(sign uint64) float64 {
	if sign == 1 {
		return -1
	}
	return 1
}
