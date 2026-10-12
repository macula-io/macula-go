package frame

import (
	"errors"
	"slices"

	"github.com/macula-io/macula-go/cbor"
)

// Wire 1.0's unknown enum values (macula docs/design/WIRE_1_0.md section 3.4,
// macula#99): an unknown value never closes a link. In a per-hop slot it reads
// as the enum's fallback and is counted (wire_enum_fallback, by field); inside
// a signed tbs it refuses that object with EnumUnknownError naming the field.

// ErrEnumUnknown is a signed object carrying an enum value its reader does not
// know (enum_unknown). The refusal is an *EnumUnknownError naming the field.
var ErrEnumUnknown = errors.New("frame: enum_unknown")

// EnumUnknownError is enum_unknown naming the field whose value the reader does
// not know.
type EnumUnknownError struct {
	Field string
}

func (e *EnumUnknownError) Error() string { return "frame: enum_unknown: " + e.Field }

func (e *EnumUnknownError) Unwrap() error { return ErrEnumUnknown }

// maxEnumValueBytes bounds an enum value on the wire: text of 1 to 64 bytes,
// whether or not the reader knows it.
const maxEnumValueBytes = 64

// enumText accepts any enum value's shape: text of 1 to 64 bytes. Whether the
// value is known is the reader's next check, not the shape's.
func enumText(v cbor.Value) bool {
	s, isText := v.AsText()
	return isText && s != "" && len(s) <= maxEnumValueBytes
}

// ReadPerHopEnum reads a per-hop enum value of field: one of known reads as
// itself, and any other as fallback, counted under field.
func ReadPerHopEnum(field, value, fallback string, known ...string) string {
	if slices.Contains(known, value) {
		return value
	}
	countEnumFallback(field)
	return fallback
}

// tbsEnum refuses a signed object whose field holds a value outside known,
// naming the field. An absent field is not judged here.
func tbsEnum(fields map[string]cbor.Value, field string, known ...string) error {
	value, has := fields[field]
	if !has {
		return nil
	}
	if s, _ := value.AsText(); !slices.Contains(known, s) {
		return &EnumUnknownError{Field: field}
	}
	return nil
}

// DeliveredVia is how a received EVENT says its publication reached this
// node: plumtree or direct, and any value this library does not know reads as
// direct, counted (WIRE_1_0.md section 3.4).
func DeliveredVia(event cbor.Value) string {
	value, _ := event.Get("delivered_via")
	via, _ := value.AsText()
	return ReadPerHopEnum("delivered_via", via, "direct", "plumtree", "direct")
}
