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
			procedure := c.Text("procedure")
			if c.Text("args") != "" {
				dhtArgsCase(t, c, procedure)
				return
			}
			raw, err := c.Hex("reply")
			if err != nil {
				t.Fatal(err)
			}
			reply, err := cbor.Decode(raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			read, err := readDHTReply(procedure, reply)
			switch c.Outcome() {
			case "refuse":
				want := map[string]error{"malformed_reply": ErrMalformedReply, "reply_version_unsupported": ErrReplyVersionUnsupported}[c.Reason()]
				if want == nil || !errors.Is(err, want) {
					t.Fatalf("%v, want %s", err, c.Reason())
				}
				return
			case "accept":
				if err != nil {
					t.Fatalf("%v, want it read", err)
				}
			}
			if read.result != c.ExpectText("result") {
				t.Errorf("result %q, want %q", read.result, c.ExpectText("result"))
			}
			if reason := c.ExpectText("reason"); reason != "" {
				if got, _ := read.fields["reason"].AsText(); got != reason {
					t.Errorf("reason %q, want %q", got, reason)
				}
			}
			if _, has := c.Expect["records_kept"]; has {
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
		})
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
