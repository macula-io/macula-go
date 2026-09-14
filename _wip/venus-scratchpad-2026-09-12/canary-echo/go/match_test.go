package main

import (
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// The match rule must see through text/bytes and key order, and exact must not.
func TestMatchRule(t *testing.T) {
	sent := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Text("1")},
		{Key: cbor.Text("b"), Val: cbor.Text("2")},
	})
	reordered := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("b"), Val: cbor.Text("2")},
		{Key: cbor.Text("a"), Val: cbor.Text("1")},
	})
	asBytes := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Bytes([]byte("1"))},
		{Key: cbor.Text("b"), Val: cbor.Text("2")},
	})
	different := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("a"), Val: cbor.Text("1")},
		{Key: cbor.Text("b"), Val: cbor.Text("3")},
	})
	if contentOf(sent) != contentOf(reordered) || contentOf(sent) != contentOf(asBytes) {
		t.Fatal("content match must ignore key order and text versus bytes")
	}
	if contentOf(sent) == contentOf(different) {
		t.Fatal("content match must still catch a changed value")
	}
	if contentOf(cbor.Text("hello")) != contentOf(cbor.Bytes([]byte("hello"))) {
		t.Fatal("text and bytes with the same content must match")
	}
	if contentOf(cbor.Text("ab")) == contentOf(cbor.Text("a")) {
		t.Fatal("different lengths must not match")
	}
}
