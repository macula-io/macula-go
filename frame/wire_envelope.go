package frame

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/macula-io/macula-go/cbor"
)

// Wire 1.0's frame envelope (macula docs/design/WIRE_1_0.md section 3,
// macula#99): every frame, of every type, carries version 5 and a frame_type of
// 1 to 64 bytes, and its other envelope keys only when it has a value for them.
// Additions arrive in ext, never as new core fields.

// ErrExtensionUnsupported is a frame or signed object carrying a critical
// extension its receiver does not know (extension_unsupported).
var ErrExtensionUnsupported = errors.New("frame: extension_unsupported")

// The bounds of a frame_type, an extension name and an ext map.
const (
	maxFrameTypeBytes     = 64
	maxExtensionNameBytes = 64
	maxExtensions         = 16
)

// knownExtensions are the extensions this library acts on. Wire 1.0 defines
// none; each one arrives with the capability bit that announces it.
var knownExtensions = map[string]bool{}

// Envelope is a received frame as wire 1.0 reads it: its type, and the frame
// with any ignored extensions read past, so the type's own table never sees
// ext.
type Envelope struct {
	FrameType string
	Frame     cbor.Value
}

// envelopeRules are the envelope keys every frame type shares, other than
// version, frame_type and ext, which ReadEnvelope reads itself. source_route is
// bytes, as macula_frame carries it (WIRE_1_0.md section 3.1); its reply and
// relay error forms, source_route_reverse and source_route_partial, are those
// frames' own fields.
var envelopeRules = map[string]fieldRule{
	"frame_id":     bytesOf(16),
	"sent_at_ms":   protocolUint,
	"realm":        bytesOf(32),
	"call_id":      bytesOf(16),
	"source_route": anyBytes,
}

// ReadEnvelope reads a received frame's envelope: version 5, a frame_type of 1
// to 64 bytes, every shared envelope key of its type, and an ext map of 1 to
// 16 well-formed extensions. An unknown critical extension is
// ErrExtensionUnsupported; an unknown non-critical one is counted and read
// past. Any other fault is ErrMalformedFrame. Keys beyond the envelope are the
// frame type's own, for its table to judge.
func ReadEnvelope(v cbor.Value) (Envelope, error) {
	entries, isMap := v.AsMap()
	if !isMap {
		return Envelope{}, ErrMalformedFrame
	}
	var frameType string
	var hasVersion bool
	kept := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		name, err := envelopeEntry(e)
		if err != nil {
			return Envelope{}, err
		}
		switch name {
		case "ext":
			// Acted on already, and not part of the frame it carries.
			continue
		case "version":
			hasVersion = true
		case "frame_type":
			frameType, _ = e.Val.AsText()
		}
		kept = append(kept, e)
	}
	if !hasVersion || frameType == "" {
		return Envelope{}, ErrMalformedFrame
	}
	return Envelope{FrameType: frameType, Frame: cbor.Map(kept)}, nil
}

// envelopeEntry judges one envelope entry, and returns its name.
func envelopeEntry(e cbor.MapEntry) (string, error) {
	name, isText := e.Key.AsText()
	if !isText {
		return "", ErrMalformedFrame
	}
	switch name {
	case "version":
		if n, isInt := e.Val.AsInt64(); !isInt || n != ProtocolVersion {
			return "", fmt.Errorf("%w: version %+v", ErrMalformedFrame, e.Val)
		}
	case "frame_type":
		text, isText := e.Val.AsText()
		if !isText || text == "" || len(text) > maxFrameTypeBytes {
			return "", fmt.Errorf("%w: frame_type", ErrMalformedFrame)
		}
	case "ext":
		if err := readExt(e.Val); err != nil {
			return "", err
		}
	case "capabilities":
		return "", fmt.Errorf("%w: the dropped capabilities header", ErrMalformedFrame)
	default:
		if rule, shared := envelopeRules[name]; shared && !rule(e.Val) {
			return "", fmt.Errorf("%w: %s", ErrMalformedFrame, name)
		}
	}
	return name, nil
}

// readExt judges an ext map (CheckExt) and acts on it (ActOnExt).
func readExt(v cbor.Value) error {
	if err := CheckExt(v); err != nil {
		return err
	}
	return ActOnExt(v)
}

// CheckExt judges an ext map's shape alone (WIRE_1_0.md section 3.2): 1 to 16
// entries, each a name of 1 to 64 bytes of [a-z0-9_.] mapped to exactly
// {critical 0 or 1, value}, else ErrMalformedFrame. It acts on nothing, as a
// custodian storing a record that carries ext does not.
func CheckExt(v cbor.Value) error {
	_, err := extEntries(v)
	return err
}

// ExtensionUnsupportedError is ErrExtensionUnsupported naming every unknown
// critical extension the ext map carries, ascending.
type ExtensionUnsupportedError struct {
	Names []string
}

func (e *ExtensionUnsupportedError) Error() string {
	return fmt.Sprintf("%v: %s", ErrExtensionUnsupported, strings.Join(e.Names, ", "))
}

// Is makes an ExtensionUnsupportedError match ErrExtensionUnsupported.
func (e *ExtensionUnsupportedError) Is(target error) bool { return target == ErrExtensionUnsupported }

// extOf judges an extension map's shape alone, as a signed object's tbs holds
// it (WIRE_1_0.md section 3.2): 1 to 16 well-formed entries. What the receiver
// does with them is readTBSExt's, once the object's own fields have read.
func extOf(v cbor.Value) bool {
	return CheckExt(v) == nil
}

// ActOnExt acts on a well-formed ext map as a receiver that knows no
// extension: an unknown critical one is ErrExtensionUnsupported, and only when
// none is, each unknown non-critical one is counted under its name.
func ActOnExt(v cbor.Value) error {
	critical, err := extEntries(v)
	if err != nil {
		return err
	}
	var refused []string
	for name, isCritical := range critical {
		if !knownExtensions[name] && isCritical {
			refused = append(refused, name)
		}
	}
	if refused != nil {
		slices.Sort(refused)
		return &ExtensionUnsupportedError{Names: refused}
	}
	for name := range critical {
		if !knownExtensions[name] {
			countExtIgnored(name)
		}
	}
	return nil
}

// extEntries is a well-formed ext map's entries, name to critical.
func extEntries(v cbor.Value) (map[string]bool, error) {
	entries, isMap := v.AsMap()
	if !isMap || len(entries) == 0 || len(entries) > maxExtensions {
		return nil, fmt.Errorf("%w: ext", ErrMalformedFrame)
	}
	critical := make(map[string]bool, len(entries))
	for _, e := range entries {
		name, isText := e.Key.AsText()
		_, seen := critical[name]
		if !isText || seen || !extensionName(name) {
			return nil, fmt.Errorf("%w: an extension name", ErrMalformedFrame)
		}
		isCritical, ok := extensionCriticality(e.Val)
		if !ok {
			return nil, fmt.Errorf("%w: extension %s", ErrMalformedFrame, name)
		}
		critical[name] = isCritical
	}
	return critical, nil
}

func zeroOrOne(v cbor.Value) bool {
	n, isInt := v.AsInt64()
	return isInt && (n == 0 || n == 1)
}

// extensionCriticality is an extension's criticality: a map of exactly
// {critical: 0 or 1, value: anything}. The value is an extension's own, so the
// decoding rule that refuses CBOR null in a protocol field does not reach it,
// as it does not reach a payload (WIRE_1_0.md sections 3.1 and 3.2).
func extensionCriticality(v cbor.Value) (bool, bool) {
	entries, isMap := v.AsMap()
	if !isMap || len(entries) != 2 {
		return false, false
	}
	var flag int64
	var hasCritical, hasValue bool
	for _, e := range entries {
		name, _ := e.Key.AsText()
		switch name {
		case "critical":
			n, isInt := e.Val.AsInt64()
			flag, hasCritical = n, isInt && (n == 0 || n == 1)
		case "value":
			hasValue = true
		default:
			return false, false
		}
	}
	return flag == 1, hasCritical && hasValue
}

func extensionName(name string) bool {
	if name == "" || len(name) > maxExtensionNameBytes {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.') {
			return false
		}
	}
	return true
}
