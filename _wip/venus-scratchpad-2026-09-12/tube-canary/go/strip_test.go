package main

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

func clip(name string, views int64) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("name"), Val: cbor.Bytes([]byte(name))},
		{Key: cbor.Text("view_count"), Val: cbor.Int(views)},
	})
}

func TestDigestIgnoresViewCountsAndKeyOrderButNotContent(t *testing.T) {
	a := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("name"), Val: cbor.Bytes([]byte("The BEAM Channel"))},
		{Key: cbor.Text("clips"), Val: cbor.List([]cbor.Value{clip("one", 3), clip("two", 7)})},
	})
	b := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("clips"), Val: cbor.List([]cbor.Value{clip("one", 4), clip("two", 9)})},
		{Key: cbor.Text("name"), Val: cbor.Bytes([]byte("The BEAM Channel"))},
	})
	c := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("name"), Val: cbor.Bytes([]byte("Another Channel"))},
		{Key: cbor.Text("clips"), Val: cbor.List([]cbor.Value{clip("one", 3), clip("two", 7)})},
	})
	sa, ca := stripViewCounts(a)
	sb, cb := stripViewCounts(b)
	sc, _ := stripViewCounts(c)
	if !bytes.Equal(cbor.Encode(sa), cbor.Encode(sb)) {
		t.Fatal("the same content with other view counts and key order must digest the same")
	}
	if bytes.Equal(cbor.Encode(sa), cbor.Encode(sc)) {
		t.Fatal("a changed name must change the digest")
	}
	if len(ca) != 2 || ca[0] != 3 || ca[1] != 7 || len(cb) != 2 || cb[0] != 4 || cb[1] != 9 {
		t.Fatalf("view counts not reported in order: %v %v", ca, cb)
	}
}

func TestStreamHazardIsCancelledWithBadRequestBeforeData(t *testing.T) {
	aborted := func(code, message string, chunks int) map[string]any {
		return map[string]any{"outcome": "peer_aborted", "code": code, "message": message, "chunks": chunks}
	}
	if !isStreamHazard(aborted("cancelled", "bad_request", 0)) {
		t.Fatal("cancelled with bad_request before any data is the hazard")
	}
	if isStreamHazard(aborted("cancelled", "bad_request", 3)) {
		t.Fatal("after data has arrived it is a failure, not the hazard")
	}
	if isStreamHazard(aborted("cancelled", "not_found", 0)) {
		t.Fatal("another reason is a failure")
	}
	if isStreamHazard(aborted("bad_request", "bad_request", 0)) {
		t.Fatal("only code cancelled is the hazard")
	}
	if isStreamHazard(map[string]any{"outcome": "ok", "chunks": 0}) {
		t.Fatal("a clean end is not the hazard")
	}
}
