package stationlink

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

// The wire 1.0 _dht.* vectors (macula priv/vectors/wire_1_0/dht_procedures.json,
// macula#102). Replies are read as this client reads them; an argument form a
// station accepts must be exactly what this client sends for the same field; one
// a station refuses as malformed_args is checked against the station reading
// the test stations here hold to.
func TestTheWireOneDHTVectors(t *testing.T) {
	f, err := wire10vectors.Load("dht_procedures")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			assertADHTVector(t, c)
		})
	}
}

// assertADHTVector applies one vector: an arguments case to the station
// reading the test stations hold to, a reply case to this client's reader,
// which must refuse or read it as the vector says.
func assertADHTVector(t *testing.T, c wire10vectors.Case) {
	t.Helper()
	procedure := c.Text("procedure")
	if c.Text("args") != "" {
		dhtArgsCase(t, c, procedure)
		return
	}
	read, err := readDHTReplyVector(t, c, procedure)
	if c.Outcome() == "refuse" {
		assertDHTRefusal(t, c, err)
		return
	}
	if c.Outcome() == "accept" && err != nil {
		t.Fatalf("%v, want it read", err)
	}
	assertDHTReplyFields(t, c, read)
}

// readDHTReplyVector reads a reply case's bytes as this client reads them.
func readDHTReplyVector(t *testing.T, c wire10vectors.Case, procedure string) (dhtReplyFields, error) {
	t.Helper()
	raw, err := c.Hex("reply")
	if err != nil {
		t.Fatal(err)
	}
	reply, err := cbor.Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return readDHTReply(procedure, reply)
}

// assertDHTRefusal checks the reader refused for the reason the vector names.
func assertDHTRefusal(t *testing.T, c wire10vectors.Case, err error) {
	t.Helper()
	want := map[string]error{"malformed_reply": ErrMalformedReply, "reply_version_unsupported": ErrReplyVersionUnsupported}[c.Reason()]
	if want == nil || !errors.Is(err, want) {
		t.Fatalf("%v, want %s", err, c.Reason())
	}
}

// assertDHTReplyFields checks the result a reply read to, its reason when the
// vector names one, and the records a find_records reply kept verified.
func assertDHTReplyFields(t *testing.T, c wire10vectors.Case, read dhtReplyFields) {
	t.Helper()
	if read.result != c.ExpectText("result") {
		t.Errorf("result %q, want %q", read.result, c.ExpectText("result"))
	}
	assertDHTReason(t, c, read)
	if _, has := c.Expect["records_kept"]; has {
		assertRecordsKept(t, c, read)
	}
}

// assertDHTReason checks the reason field when the vector names one.
func assertDHTReason(t *testing.T, c wire10vectors.Case, read dhtReplyFields) {
	t.Helper()
	reason := c.ExpectText("reason")
	if reason == "" {
		return
	}
	if got, _ := read.fields["reason"].AsText(); got != reason {
		t.Errorf("reason %q, want %q", got, reason)
	}
}

// assertRecordsKept counts the reply's records that verify and checks the
// vector's count of the ones a station kept.
func assertRecordsKept(t *testing.T, c wire10vectors.Case, read dhtReplyFields) {
	t.Helper()
	items, _ := read.fields["records"].AsList()
	kept := 0
	for _, item := range items {
		wire, _ := item.AsBytes()
		if _, err := record.Verify(wire, profile.Profile(c.Profile), c.Int("now_ms")); err == nil {
			kept++
		} else {
			t.Logf("a record dropped: %v", err)
		}
	}
	if int64(kept) != c.ExpectInt("records_kept") {
		t.Errorf("%d records kept, want %d", kept, c.ExpectInt("records_kept"))
	}
}

func dhtArgsCase(t *testing.T, c wire10vectors.Case, procedure string) {
	t.Helper()
	raw, err := c.Hex("args")
	if err != nil {
		t.Fatal(err)
	}
	args, err := cbor.Decode(raw)
	if err != nil {
		if c.Outcome() == "refuse" {
			return
		}
		t.Fatalf("decode: %v", err)
	}
	value, accepted := stationReadsArgs(procedure, args)
	if accepted != (c.Outcome() == "accept") {
		t.Fatalf("a station reading these arguments accepts them: %t, want %s", accepted, c.Outcome())
	}
	if accepted {
		if sent := cbor.Encode(dhtArgs(dhtArgFields[procedure].name, value)); !bytes.Equal(sent, raw) {
			t.Errorf("this client sends %x for the same field, want %x", sent, raw)
		}
	}
}
