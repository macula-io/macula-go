package frame

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"unicode/utf8"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
)

// The labels of the signed objects that requests, replies and relay errors
// carry (D25).
const (
	requestLabel    = "MACULA-PQ-REQUEST-V1"
	replyLabel      = "MACULA-PQ-REPLY-V1"
	relayErrorLabel = "MACULA-PQ-RELAY-ERROR-V1"
)

// The bounds of a signed frame's fields: a protocol integer stays below 2^53,
// a procedure name is at most 512 bytes, an error code at most 64, and an
// error's text for people at most 256.
const (
	maxProtocolInt    = 1 << 53
	maxProcedureBytes = 512
	maxErrorCodeBytes = 64
	maxErrorTextBytes = 256
)

// The refusals of a signed frame, named as macula_frame names them. A signature
// that does not verify is identity.ErrObjectSignatureInvalid, and a binary
// without ML-DSA refuses with identity.ErrPostQuantumUnavailable.
var (
	// ErrMalformedFrame is a frame, or the signed object it carries, without
	// exactly the shape and fields of its type.
	ErrMalformedFrame = errors.New("frame: malformed frame")
	// ErrKeyIDMismatch is a signed object whose caller, responded_by or
	// reported_by is not the key id of the key it verified with.
	ErrKeyIDMismatch = errors.New("frame: the signer the frame names is not the key it verified with")
	// ErrRequestMismatch is a reply or relay error whose request_id or
	// request_hash names another request.
	ErrRequestMismatch = errors.New("frame: the frame names another request")
	// ErrNotTheTarget is a reply from a node other than its request's target.
	ErrNotTheTarget = errors.New("frame: the reply is not from the request's target")
	// ErrNotTheConnection is a relay error reported by a station other than
	// the one the connection authenticated.
	ErrNotTheConnection = errors.New("frame: the relay error is not from the connection's station")
	// ErrUnsignable is a build whose key is not an identity key, or not the
	// sender the receiver verifies.
	ErrUnsignable = errors.New("frame: the key cannot sign this frame")
	// ErrTextTooLong is a build whose procedure, code or detail is longer than
	// its bound.
	ErrTextTooLong = errors.New("frame: text longer than its bound")
	// ErrInvalidText is a build whose procedure, code or detail is not valid
	// UTF-8.
	ErrInvalidText = errors.New("frame: text that is not valid UTF-8")
	// ErrRelayCodeOutsideItsSet is a relay error build whose code is not in
	// the closed set of relay codes.
	ErrRelayCodeOutsideItsSet = errors.New("frame: a relay error code outside its closed set")
	// ErrOutOfRange is a build whose frame type, stream mode, deadline or
	// retry budget is outside its set or range.
	ErrOutOfRange = errors.New("frame: a field outside its range")
)

// relayCodes is the closed set of relay error codes, disjoint from every
// provider code (D25).
var relayCodes = []string{"unknown_next_peer"}

// fieldRule reports whether a field's value is one its table accepts.
type fieldRule func(cbor.Value) bool

func anyValue(cbor.Value) bool { return true }

func anyBytes(v cbor.Value) bool {
	_, isBytes := v.AsBytes()
	return isBytes
}

func bytesOf(size int) fieldRule {
	return func(v cbor.Value) bool {
		b, isBytes := v.AsBytes()
		return isBytes && len(b) == size
	}
}

func textWithin(max int) fieldRule {
	return func(v cbor.Value) bool {
		s, isText := v.AsText()
		return isText && len(s) <= max
	}
}

func textIn(names ...string) fieldRule {
	return func(v cbor.Value) bool {
		s, isText := v.AsText()
		return isText && slices.Contains(names, s)
	}
}

func protocolUint(v cbor.Value) bool {
	n, isInt := v.AsInt64()
	return isInt && n >= 0 && n < maxProtocolInt
}

func protocolVersion(v cbor.Value) bool {
	n, isInt := v.AsInt64()
	return isInt && n == ProtocolVersion
}

func carriedObject(v cbor.Value) bool {
	_, err := identity.ParseObject(v)
	return err == nil
}

// readFields reads a map through its table, as macula_frame's read_fields does:
// every key text, named in the table and there once, with a value its rule
// accepts. It returns the values by name.
func readFields(v cbor.Value, table map[string]fieldRule) (map[string]cbor.Value, bool) {
	entries, isMap := v.AsMap()
	if !isMap {
		return nil, false
	}
	fields := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		name, isText := e.Key.AsText()
		rule, known := table[name]
		_, seen := fields[name]
		if !isText || !known || seen || !rule(e.Val) {
			return nil, false
		}
		fields[name] = e.Val
	}
	return fields, true
}

// hasFields reports whether fields holds every one of names.
func hasFields(fields map[string]cbor.Value, names ...string) bool {
	for _, name := range names {
		if _, has := fields[name]; !has {
			return false
		}
	}
	return true
}

// receivedFrame reads a received frame that carries its fields in one signed
// object, with the checks a received frame passes before its object is
// verified: exactly version, frame_type, the object under objectName and the
// routing fields routes names; the protocol's version; a frame type of types;
// the object a map of exactly key, tbs and signature byte strings; and each
// routing field of its rule. It returns the frame type and the object.
func receivedFrame(v cbor.Value, objectName string, routes map[string]fieldRule, types ...string) (string, cbor.Value, bool) {
	table := map[string]fieldRule{"version": protocolVersion, "frame_type": textIn(types...), objectName: carriedObject}
	maps.Copy(table, routes)
	fields, ok := readFields(v, table)
	if !ok || !hasFields(fields, "version", "frame_type", objectName) {
		return "", cbor.Value{}, false
	}
	frameType, _ := fields["frame_type"].AsText()
	return frameType, fields[objectName], true
}

// objectRefusal is the refusal of a frame whose signed object did not verify:
// a signature that does not verify and a binary without ML-DSA as they are, and
// any other refusal as ErrMalformedFrame.
func objectRefusal(err error) error {
	if errors.Is(err, identity.ErrObjectSignatureInvalid) || errors.Is(err, identity.ErrPostQuantumUnavailable) {
		return err
	}
	return fmt.Errorf("%w: %w", ErrMalformedFrame, err)
}

// boundedText refuses text longer than max bytes, judged first, and then text
// that is not valid UTF-8, naming the field.
func boundedText(field, text string, max int) error {
	switch {
	case len(text) > max:
		return fmt.Errorf("%w: a %s of %d bytes, over %d", ErrTextTooLong, field, len(text), max)
	case !utf8.ValidString(text):
		return fmt.Errorf("%w: the %s", ErrInvalidText, field)
	}
	return nil
}

// identitySigner refuses a key that is not an identity key holding a key.
func identitySigner(key *identity.NodeKey) error {
	if key == nil || key.Purpose() != identity.PurposeIdentity || key.PublicKey() == nil {
		return ErrUnsignable
	}
	return nil
}

func textEntry(name, value string) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Text(value)}
}

func bytesEntry(name string, value []byte) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Bytes(value)}
}

func uintEntry(name string, value uint64) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: cbor.Uint64(value)}
}

func valueEntry(name string, value cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(name), Val: value}
}

// fixedBytes copies a byte string field into dst, which its rule sized.
func fixedBytes(dst []byte, v cbor.Value) {
	b, _ := v.AsBytes()
	copy(dst, b)
}

func textOf(v cbor.Value) string {
	s, _ := v.AsText()
	return s
}

func optionalText(fields map[string]cbor.Value, name string) *string {
	v, has := fields[name]
	if !has {
		return nil
	}
	s, _ := v.AsText()
	return &s
}
