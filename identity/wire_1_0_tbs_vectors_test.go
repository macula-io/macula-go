package identity

import (
	"bytes"
	"encoding/hex"
	"sort"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 tbs vectors (macula priv/vectors/wire_1_0/tbs.json, macula#97):
// every signed structure's fields, the canonical tbs a stack must encode from
// them, its signing input (keyed: label, 0x00, SHA-384 of the key as carried,
// tbs; unkeyed: label, 0x00, tbs) and a signature over it under the signer's
// fixed key. This library's deterministic encoding and signing inputs must
// reproduce both byte for byte.

func TestTheWireOneTBSVectors(t *testing.T) {
	f, err := wire10vectors.Load("tbs")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := wire10vectors.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) { checkTBSVector(t, c, keys) })
	}
}

// checkTBSVector checks one vector: fields encode to its tbs, the tbs under its
// label and signer is its signing input, and the vector's signature verifies
// over that input.
func checkTBSVector(t *testing.T, c wire10vectors.Case, keys wire10vectors.Keys) {
	t.Helper()
	fields, _ := c.Input["fields"].(map[string]any)
	tbs := cbor.Encode(typedValue(t, fields))
	if want := expectHex(t, c, "tbs"); !bytes.Equal(tbs, want) {
		t.Fatalf("tbs\n got %x\nwant %x", tbs, want)
	}
	key, err := keys.Key(c.Profile, c.Text("signer"))
	if err != nil {
		t.Fatal(err)
	}
	input := signingInput(t, c, key, tbs)
	if want := expectHex(t, c, "signing_input"); !bytes.Equal(input, want) {
		t.Fatalf("signing input\n got %x\nwant %x", input, want)
	}
	if !Verify(input, expectHex(t, c, "signature"), key, profile.Profile(c.Profile)) {
		t.Errorf("the signature does not verify over the signing input")
	}
}

// signingInput is the vector's signing input: a keyed structure's label, a zero
// byte and the sha384 of the key as carried, or an unkeyed structure's label
// and a zero byte, before the tbs.
func signingInput(t *testing.T, c wire10vectors.Case, key, tbs []byte) []byte {
	t.Helper()
	switch c.Text("form") {
	case "keyed":
		return objectSignedBytes(c.Text("label"), key, tbs)
	case "unkeyed":
		return labelled(c.Text("label"), tbs)
	}
	t.Fatalf("form %q has no signing input here", c.Text("form"))
	return nil
}

func expectHex(t *testing.T, c wire10vectors.Case, name string) []byte {
	t.Helper()
	s, _ := c.Expect[name].(string)
	b, err := hex.DecodeString(s)
	if err != nil || s == "" {
		t.Fatalf("expect.%s: %q, %v", name, s, err)
	}
	return b
}

// typedValue is the CBOR value of a typed JSON value (FORMAT.md, Values): a
// number an integer, a string text, {"$hex": ...} bytes, an object a map with
// text keys, an array an array, null null.
func typedValue(t *testing.T, v any) cbor.Value {
	t.Helper()
	switch v := v.(type) {
	case nil:
		return cbor.Null()
	case float64:
		if v < 0 {
			return cbor.Int(int64(v))
		}
		return cbor.Uint64(uint64(v))
	case string:
		return cbor.Text(v)
	case []any:
		items := make([]cbor.Value, len(v))
		for i, item := range v {
			items[i] = typedValue(t, item)
		}
		return cbor.List(items)
	case map[string]any:
		return typedMapValue(t, v)
	}
	t.Fatalf("a typed JSON value of %T", v)
	return cbor.Value{}
}

// typedMapValue is a typed JSON object: {"$hex": ...} is a byte string, and any
// other object a map with text keys in sorted order.
func typedMapValue(t *testing.T, v map[string]any) cbor.Value {
	t.Helper()
	if h, isHex := v["$hex"].(string); isHex && len(v) == 1 {
		b, err := hex.DecodeString(h)
		if err != nil {
			t.Fatalf("$hex %q: %v", h, err)
		}
		return cbor.Bytes(b)
	}
	names := make([]string, 0, len(v))
	for name := range v {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]cbor.MapEntry, len(names))
	for i, name := range names {
		entries[i] = cbor.MapEntry{Key: cbor.Text(name), Val: typedValue(t, v[name])}
	}
	return cbor.Map(entries)
}
