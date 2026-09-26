package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/macula-io/macula-go/cbor"
)

// A payload crosses the ABI as JSON text, mapped to and from macula's CBOR
// (CONTRACT.md "Payloads"):
//
//   - No boolean: macula's CBOR has none, so true and false are refused, not
//     turned into 0 and 1.
//   - Bytes are the object {"$bytes": "<standard padded base64>"} with that
//     sole key, in both directions, so a value received can be sent back.
//     Any other value under a sole "$bytes" key is refused; an object with
//     more keys is an ordinary map.
//   - A number with no fraction or exponent is an integer, exact over the
//     int64 range, which is the wire's: macula's decoding rule refuses any
//     integer outside it, so one is refused here before it is sent. Any
//     other number is a float.

const bytesKey = "$bytes"

// payloadFromJSON is the CBOR value of a JSON payload; "" is null.
func payloadFromJSON(text string) (cbor.Value, error) {
	if text == "" {
		return cbor.Null(), nil
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var v any
	if err := decoder.Decode(&v); err != nil {
		return cbor.Value{}, invalidArgument("the payload is not JSON: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return cbor.Value{}, invalidArgument("the payload has more than one JSON value")
	}
	return valueFromJSON(v)
}

func valueFromJSON(v any) (cbor.Value, error) {
	switch t := v.(type) {
	case nil:
		return cbor.Null(), nil
	case bool:
		return cbor.Value{}, invalidArgument("JSON %v has no wire form: macula's CBOR has no boolean, send 0 or 1", t)
	case string:
		return cbor.Text(t), nil
	case json.Number:
		return numberFromJSON(t)
	case []any:
		items := make([]cbor.Value, len(t))
		for i, item := range t {
			value, err := valueFromJSON(item)
			if err != nil {
				return cbor.Value{}, err
			}
			items[i] = value
		}
		return cbor.List(items), nil
	case map[string]any:
		if raw, tagged := t[bytesKey]; tagged && len(t) == 1 {
			return bytesFromJSON(raw)
		}
		entries := make([]cbor.MapEntry, 0, len(t))
		for k, item := range t {
			value, err := valueFromJSON(item)
			if err != nil {
				return cbor.Value{}, err
			}
			entries = append(entries, cbor.MapEntry{Key: cbor.Text(k), Val: value})
		}
		return cbor.Map(entries), nil
	}
	return cbor.Value{}, invalidArgument("a JSON value of type %T", v)
}

func numberFromJSON(n json.Number) (cbor.Value, error) {
	text := n.String()
	if !strings.ContainsAny(text, ".eE") {
		i, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return cbor.Value{}, invalidArgument("the integer %s is outside the wire's int64 range", text)
		}
		return cbor.Int(i), nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) {
		return cbor.Value{}, invalidArgument("the number %s is outside the float64 range", text)
	}
	return cbor.Float(f), nil
}

func bytesFromJSON(raw any) (cbor.Value, error) {
	s, ok := raw.(string)
	if !ok {
		return cbor.Value{}, invalidArgument(`a {"$bytes": ...} value must be a base64 string, not %T`, raw)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return cbor.Value{}, invalidArgument(`{"$bytes": ...} is not standard padded base64: %v`, err)
	}
	return cbor.Bytes(b), nil
}

// payloadToJSON is a CBOR value as the JSON text the ABI returns.
func payloadToJSON(v cbor.Value) json.RawMessage {
	var buf bytes.Buffer
	writeJSON(&buf, v)
	return buf.Bytes()
}

// writeJSON writes v as JSON.
func writeJSON(buf *bytes.Buffer, v cbor.Value) {
	switch v.Kind() {
	case cbor.KindUInt, cbor.KindNegInt:
		// Integers are written from their own digits, never through a
		// float. One outside int64 cannot come off the wire, which
		// refuses it; it is written as null rather than as a wrong number.
		i, ok := v.AsInt64()
		if !ok {
			buf.WriteString("null")
			return
		}
		buf.WriteString(strconv.FormatInt(i, 10))
	case cbor.KindBytes:
		b, _ := v.AsBytes()
		text, _ := json.Marshal(map[string]string{bytesKey: base64.StdEncoding.EncodeToString(b)})
		buf.Write(text)
	case cbor.KindText:
		s, _ := v.AsText()
		text, _ := json.Marshal(s)
		buf.Write(text)
	case cbor.KindFloat:
		f, _ := v.AsFloat()
		if math.IsNaN(f) || math.IsInf(f, 0) {
			buf.WriteString("null")
			return
		}
		// A float keeps a fraction or an exponent, so it parses back as
		// a float, never as an integer.
		text := strconv.FormatFloat(f, 'g', -1, 64)
		if !strings.ContainsAny(text, ".eE") {
			text += ".0"
		}
		buf.WriteString(text)
	case cbor.KindNull:
		buf.WriteString("null")
	case cbor.KindList:
		items, _ := v.AsList()
		buf.WriteByte('[')
		for i, item := range items {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeJSON(buf, item)
		}
		buf.WriteByte(']')
	case cbor.KindMap:
		entries, _ := v.AsMap()
		buf.WriteByte('{')
		for i, e := range entries {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, ok := e.Key.AsText()
			if !ok {
				key = e.Key.String()
			}
			text, _ := json.Marshal(key)
			buf.Write(text)
			buf.WriteByte(':')
			writeJSON(buf, e.Val)
		}
		buf.WriteByte('}')
	default:
		buf.WriteString("null")
	}
}
