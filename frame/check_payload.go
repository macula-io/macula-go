package frame

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/macula-io/macula-go/cbor"
)

// MaxPayloadNesting is how many lists and maps a payload may nest, the
// outermost counted. A payload travels as a value inside a frame's map, which
// takes one of the decoding rule's cbor.MaxNestingDepth levels.
const MaxPayloadNesting = cbor.MaxNestingDepth - 1

// FrameReservedElements is how many of the decoding rule's cbor.MaxElements
// items a payload leaves for the frame around it. Every frame this package
// builds with a payload, body or args holds no more items than this besides its
// payload.
const FrameReservedElements = 64

// MaxPayloadElements is how many CBOR items a payload may hold, itself
// included: every list element, map key and map value counts once, as the
// decoding rule's element budget counts them.
const MaxPayloadElements = cbor.MaxElements - FrameReservedElements

// CheckPayload reports whether v is admissible as a frame payload, the Go
// counterpart to macula_frame.erl's check_payload/1. A producer calls it in
// its own goroutine before a payload reaches a link, so a payload the
// receiving node would refuse fails here, with an error that says where,
// instead of later on the writer goroutine or as a refused frame at the other
// end.
//
// It refuses what the decoding rule refuses on arrival: a map key that is not
// text or an integer, two keys of one map that encode to the same bytes, text
// that is not valid UTF-8, an integer outside -2^63 to 2^63-1, a float that is
// NaN or infinite, lists and maps nested more than MaxPayloadNesting levels,
// and a payload of more than MaxPayloadElements items. It also refuses a
// payload whose own encoding is over the frame cap.
//
// The size check compares the payload's own encoded bytes with MaxFrameBytes,
// not the whole frame's, which adds the envelope fields. A payload within a
// few hundred bytes of the cap can still make a frame that frame.Encode
// refuses, as the reference's own check also allows.
func CheckPayload(v cbor.Value) error {
	var check payloadCheck
	if err := check.value(v, nil); err != nil {
		return err
	}
	if n := len(cbor.Encode(v)); n > MaxFrameBytes {
		return fmt.Errorf("frame: payload at %s exceeds the %d-byte frame cap (encoded %d bytes)",
			pathString(nil), MaxFrameBytes, n)
	}
	return nil
}

// payloadCheck walks a payload and counts its items.
type payloadCheck struct {
	items int
}

// value checks v, which sits at path below the payload root, and everything
// inside it.
func (c *payloadCheck) value(v cbor.Value, path []string) error {
	c.items++
	if c.items > MaxPayloadElements {
		return fmt.Errorf("frame: payload holds more than %d items, at %s", MaxPayloadElements, pathString(path))
	}
	switch v.Kind() {
	case cbor.KindFloat:
		return checkFloat(v, path)
	case cbor.KindUInt, cbor.KindNegInt:
		return checkInteger(v, path)
	case cbor.KindText:
		return checkText(v, path)
	case cbor.KindList:
		return c.list(v, path)
	case cbor.KindMap:
		return c.mapOf(v, path)
	default:
		return nil
	}
}

func checkFloat(v cbor.Value, path []string) error {
	f, _ := v.AsFloat()
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return fmt.Errorf("frame: non-finite float at %s cannot be encoded", pathString(path))
	}
	return nil
}

func checkInteger(v cbor.Value, path []string) error {
	if _, fits := v.AsInt64(); !fits {
		return fmt.Errorf("frame: integer at %s is outside -2^63 to 2^63-1", pathString(path))
	}
	return nil
}

func checkText(v cbor.Value, path []string) error {
	if s, _ := v.AsText(); !utf8.ValidString(s) {
		return fmt.Errorf("frame: text at %s is not valid UTF-8", pathString(path))
	}
	return nil
}

// checkNesting refuses a list or map at path when it would nest more than
// MaxPayloadNesting levels.
func checkNesting(path []string) error {
	if len(path) >= MaxPayloadNesting {
		return fmt.Errorf("frame: lists and maps at %s nest more than %d levels", pathString(path), MaxPayloadNesting)
	}
	return nil
}

func (c *payloadCheck) list(v cbor.Value, path []string) error {
	if err := checkNesting(path); err != nil {
		return err
	}
	items, _ := v.AsList()
	for i, item := range items {
		if err := c.value(item, append(path, strconv.Itoa(i))); err != nil {
			return err
		}
	}
	return nil
}

// mapOf checks a map's keys, which must be admissible and distinct once
// encoded, and its values.
func (c *payloadCheck) mapOf(v cbor.Value, path []string) error {
	if err := checkNesting(path); err != nil {
		return err
	}
	entries, _ := v.AsMap()
	seen := make(map[string]struct{}, len(entries))
	for _, e := range entries {
		if err := c.key(e.Key, path); err != nil {
			return err
		}
		keyBytes := string(cbor.Encode(e.Key))
		if _, dup := seen[keyBytes]; dup {
			return fmt.Errorf("frame: two keys in the map at %s collapse to the same wire key",
				pathString(path))
		}
		seen[keyBytes] = struct{}{}
		if err := c.value(e.Val, append(path, keyLabel(e.Key))); err != nil {
			return err
		}
	}
	return nil
}

// key refuses a map key the decoding rule refuses: one that is not text or an
// integer, text that is not valid UTF-8, or an integer out of range.
func (c *payloadCheck) key(k cbor.Value, path []string) error {
	switch k.Kind() {
	case cbor.KindText, cbor.KindUInt, cbor.KindNegInt:
		return c.value(k, path)
	default:
		return fmt.Errorf("frame: map key at %s is not text or an integer", pathString(path))
	}
}

func pathString(path []string) string {
	if len(path) == 0 {
		return "the payload root"
	}
	return strings.Join(path, ".")
}

func keyLabel(k cbor.Value) string {
	if s, ok := k.AsText(); ok {
		return s
	}
	return k.String()
}
