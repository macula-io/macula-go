package cbor

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Decode parses one complete CBOR value from the start of data, returning
// the value and how many bytes it consumed. Panics are not used for
// malformed input by construction — every path returns an error, since
// this parses untrusted network data (mirrors deterministic.rs's own
// panic-free-by-construction guarantee).
func Decode(data []byte) (Value, int, error) {
	return decodeOne(data)
}

func decodeOne(data []byte) (Value, int, error) {
	if len(data) < 1 {
		return Value{}, 0, fmt.Errorf("cbor: decode: empty input")
	}
	head := data[0]
	major := head >> 5
	ai := head & 0x1F
	rest := data[1:]

	switch major {
	case majorUInt:
		n, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode uint: %w", err)
		}
		return Uint64(n), 1 + used, nil

	case majorNegInt:
		n, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode negint: %w", err)
		}
		return NegInt(n), 1 + used, nil

	case majorBytes:
		length, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode bytes length: %w", err)
		}
		body := rest[used:]
		if uint64(len(body)) < length {
			return Value{}, 0, fmt.Errorf("cbor: decode bytes: need %d bytes, have %d", length, len(body))
		}
		b := make([]byte, length)
		copy(b, body[:length])
		return Bytes(b), 1 + used + int(length), nil

	case majorText:
		length, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode text length: %w", err)
		}
		body := rest[used:]
		if uint64(len(body)) < length {
			return Value{}, 0, fmt.Errorf("cbor: decode text: need %d bytes, have %d", length, len(body))
		}
		// No UTF-8 validation on decode — matches the reference encoder's
		// own leniency (§4); a Go string is just a byte sequence.
		return Text(string(body[:length])), 1 + used + int(length), nil

	case majorList:
		count, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode list length: %w", err)
		}
		pos := used
		items := make([]Value, 0, count)
		for i := uint64(0); i < count; i++ {
			item, n, err := decodeOne(rest[pos:])
			if err != nil {
				return Value{}, 0, fmt.Errorf("cbor: decode list item %d: %w", i, err)
			}
			items = append(items, item)
			pos += n
		}
		return List(items), 1 + pos, nil

	case majorMap:
		count, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, 0, fmt.Errorf("cbor: decode map length: %w", err)
		}
		pos := used
		// Last-write-wins on duplicate keys, per §4 — not an error.
		entries := make([]MapEntry, 0, count)
		for i := uint64(0); i < count; i++ {
			key, kn, err := decodeOne(rest[pos:])
			if err != nil {
				return Value{}, 0, fmt.Errorf("cbor: decode map key %d: %w", i, err)
			}
			pos += kn
			val, vn, err := decodeOne(rest[pos:])
			if err != nil {
				return Value{}, 0, fmt.Errorf("cbor: decode map value %d: %w", i, err)
			}
			pos += vn
			entries = setLastWriteWins(entries, key, val)
		}
		return Map(entries), 1 + pos, nil

	case majorFloat:
		return decodeMajor7(rest, ai)

	default: // major 6 (tags): rejected outright, not supported at all.
		return Value{}, 0, fmt.Errorf("cbor: decode: major type %d (tags) not supported", major)
	}
}

func setLastWriteWins(entries []MapEntry, key, val Value) []MapEntry {
	kb := Encode(key)
	for i := range entries {
		if bytesEqual(Encode(entries[i].Key), kb) {
			entries[i].Val = val
			return entries
		}
	}
	return append(entries, MapEntry{Key: key, Val: val})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// readAIValue reads the value ai directly encodes (ai<=23) or the
// minimal-length extra bytes it points to (ai in {24,25,26,27}) —
// shared by majors 0/1 (where this IS the value) and 2/3/4/5 (where
// it's a length). Any other ai (28-31) is a decode error: those additional-
// info values are reserved/unused in this protocol.
func readAIValue(data []byte, ai byte) (value uint64, consumed int, err error) {
	switch {
	case ai <= maxInAI:
		return uint64(ai), 0, nil
	case ai == ai1:
		if len(data) < 1 {
			return 0, 0, fmt.Errorf("need 1 more byte")
		}
		return uint64(data[0]), 1, nil
	case ai == ai2:
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("need 2 more bytes")
		}
		return uint64(binary.BigEndian.Uint16(data)), 2, nil
	case ai == ai4:
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("need 4 more bytes")
		}
		return uint64(binary.BigEndian.Uint32(data)), 4, nil
	case ai == ai8:
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("need 8 more bytes")
		}
		return binary.BigEndian.Uint64(data), 8, nil
	default:
		return 0, 0, fmt.Errorf("unsupported additional info %d", ai)
	}
}

// decodeMajor7 handles null and the three float widths — the only
// major-7 shapes this protocol uses. No booleans, no "undefined": any
// other AI is a decode error.
func decodeMajor7(data []byte, ai byte) (Value, int, error) {
	switch ai {
	case aiNull:
		return Null(), 1, nil
	case 25: // float16 -> f64
		if len(data) < 2 {
			return Value{}, 0, fmt.Errorf("cbor: decode float16: need 2 more bytes")
		}
		return Float(float16ToFloat64(binary.BigEndian.Uint16(data))), 3, nil
	case 26: // float32 -> f64
		if len(data) < 4 {
			return Value{}, 0, fmt.Errorf("cbor: decode float32: need 4 more bytes")
		}
		return Float(float64(math.Float32frombits(binary.BigEndian.Uint32(data)))), 5, nil
	case aiF64: // 27
		if len(data) < 8 {
			return Value{}, 0, fmt.Errorf("cbor: decode float64: need 8 more bytes")
		}
		return Float(math.Float64frombits(binary.BigEndian.Uint64(data))), 9, nil
	default:
		return Value{}, 0, fmt.Errorf("cbor: decode: major 7 additional info %d not supported (no booleans/undefined)", ai)
	}
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
