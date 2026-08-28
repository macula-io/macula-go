package frame

import (
	"errors"
	"fmt"

	"github.com/macula-io/macula-go-sdk/cbor"
)

// HelloInfo is the parsed contents of a HELLO frame — connect_spec's
// fields plus accepted/negotiated_capabilities/refusal_code.
type HelloInfo struct {
	NodeID                 []byte
	StationID              []byte
	Realms                 [][]byte
	Capabilities           uint64
	Accepted               bool
	NegotiatedCapabilities uint64
	RefusalCode            *int64
}

// ErrNotAHelloFrame, ErrMissingField, and ErrWrongFieldType are the
// error classes ParseHello can return; use errors.Is against these, or
// inspect the returned *ParseHelloError for the specific field name.
var (
	ErrNotAHelloFrame = errors.New("frame_type is not \"hello\"")
	ErrMissingField   = errors.New("missing required field")
	ErrWrongFieldType = errors.New("field has the wrong type")
)

// ParseHelloError names which field a missing/wrong-type error was
// about.
type ParseHelloError struct {
	Field string
	Err   error
}

func (e *ParseHelloError) Error() string {
	if e.Field == "" {
		return e.Err.Error()
	}
	return fmt.Sprintf("%s: %q", e.Err, e.Field)
}

func (e *ParseHelloError) Unwrap() error { return e.Err }

func getBytes32(v cbor.Value, field string) ([]byte, error) {
	return getBytesSized(v, field, 32)
}

// getBytesSized is getBytes32 generalized to an arbitrary fixed length
// -- e.g. stream_id/call_id are 16 bytes, not 32.
func getBytesSized(v cbor.Value, field string, n int) ([]byte, error) {
	fv, ok := v.Get(field)
	if !ok {
		return nil, &ParseHelloError{Field: field, Err: ErrMissingField}
	}
	b, ok := fv.AsBytes()
	if !ok || len(b) != n {
		return nil, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
	}
	return b, nil
}

func getBytes32List(v cbor.Value, field string) ([][]byte, error) {
	fv, ok := v.Get(field)
	if !ok {
		return nil, &ParseHelloError{Field: field, Err: ErrMissingField}
	}
	items, ok := fv.AsList()
	if !ok {
		return nil, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
	}
	out := make([][]byte, len(items))
	for i, item := range items {
		b, ok := item.AsBytes()
		if !ok || len(b) != 32 {
			return nil, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
		}
		out[i] = b
	}
	return out, nil
}

func getUint(v cbor.Value, field string) (uint64, error) {
	fv, ok := v.Get(field)
	if !ok {
		return 0, &ParseHelloError{Field: field, Err: ErrMissingField}
	}
	n, ok := fv.AsInt64()
	if !ok || n < 0 {
		return 0, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
	}
	return uint64(n), nil
}

func getBool(v cbor.Value, field string) (bool, error) {
	fv, ok := v.Get(field)
	if !ok {
		return false, &ParseHelloError{Field: field, Err: ErrMissingField}
	}
	t, ok := fv.AsText()
	if !ok {
		return false, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
	}
	switch t {
	case "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, &ParseHelloError{Field: field, Err: ErrWrongFieldType}
	}
}

// ParseHello parses a decoded frame as a HELLO, checking frame_type
// first.
func ParseHello(v cbor.Value) (HelloInfo, error) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return HelloInfo{}, &ParseHelloError{Err: ErrNotAHelloFrame}
	}
	if t, ok := ft.AsText(); !ok || t != "hello" {
		return HelloInfo{}, &ParseHelloError{Err: ErrNotAHelloFrame}
	}

	var refusalCode *int64
	if rc, ok := v.Get("refusal_code"); ok && !rc.IsNull() {
		n, ok := rc.AsInt64()
		if !ok {
			return HelloInfo{}, &ParseHelloError{Field: "refusal_code", Err: ErrWrongFieldType}
		}
		refusalCode = &n
	}

	nodeID, err := getBytes32(v, "node_id")
	if err != nil {
		return HelloInfo{}, err
	}
	stationID, err := getBytes32(v, "station_id")
	if err != nil {
		return HelloInfo{}, err
	}
	realms, err := getBytes32List(v, "realms")
	if err != nil {
		return HelloInfo{}, err
	}
	capabilities, err := getUint(v, "capabilities")
	if err != nil {
		return HelloInfo{}, err
	}
	accepted, err := getBool(v, "accepted")
	if err != nil {
		return HelloInfo{}, err
	}
	negotiated, err := getUint(v, "negotiated_capabilities")
	if err != nil {
		return HelloInfo{}, err
	}

	return HelloInfo{
		NodeID:                 nodeID,
		StationID:              stationID,
		Realms:                 realms,
		Capabilities:           capabilities,
		Accepted:               accepted,
		NegotiatedCapabilities: negotiated,
		RefusalCode:            refusalCode,
	}, nil
}
