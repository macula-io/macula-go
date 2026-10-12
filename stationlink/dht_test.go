package stationlink

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

// dhtStation answers the station's _dht.* procedures from memory, storing
// record wire bytes by their storage key, as a station's DHT slot does. It
// reads arguments as a wire 1.0 station does (WIRE_1_0.md section 6): exactly
// {v 1, ...} with the procedure's one key form, else the test fails.
type dhtStation struct {
	mu     sync.Mutex
	byKey  map[[32]byte][][]byte
	byType map[record.Type][][]byte
	extra  [][]byte // returned beside the stored records, verified or not
	refuse string   // a put_record refusal reason, when set
}

// dhtArgFields are each _dht.* procedure's one argument besides v, with its
// rule, as a wire 1.0 station reads them (WIRE_1_0.md section 6).
var dhtArgFields = map[string]struct {
	name string
	rule func(cbor.Value) bool
}{
	"_dht.put_record":           {"record", isBytes},
	"_dht.find_record":          {"key", func(v cbor.Value) bool { b, ok := v.AsBytes(); return ok && len(b) == 32 }},
	"_dht.find_records":         {"key", func(v cbor.Value) bool { b, ok := v.AsBytes(); return ok && len(b) == 32 }},
	"_dht.find_records_by_type": {"type", func(v cbor.Value) bool { n, ok := v.AsInt64(); return ok && n >= 0 && n <= 255 }},
}

// stationReadsArgs reads a _dht.* argument map as a wire 1.0 station does:
// exactly {v 1, field} with text keys and the field of its rule, else false
// (malformed_args).
func stationReadsArgs(procedure string, payload cbor.Value) (cbor.Value, bool) {
	want := dhtArgFields[procedure]
	entries, isMap := payload.AsMap()
	if !isMap || len(entries) != 2 {
		return cbor.Value{}, false
	}
	for _, e := range entries {
		if _, isText := e.Key.AsText(); !isText {
			return cbor.Value{}, false
		}
	}
	v, _ := payload.Get("v")
	n, isInt := v.AsInt64()
	value, has := payload.Get(want.name)
	if !isInt || n != 1 || !has || !want.rule(value) {
		return cbor.Value{}, false
	}
	return value, true
}

// stationArgs is stationReadsArgs failing the test on malformed arguments: the
// client must only send the one form.
func stationArgs(t *testing.T, procedure string, payload cbor.Value) cbor.Value {
	t.Helper()
	value, ok := stationReadsArgs(procedure, payload)
	if !ok {
		t.Errorf("station: %s arguments %+v, want exactly its one form", procedure, payload)
	}
	return value
}

func dhtReply(fields ...cbor.MapEntry) cbor.Value {
	return cbor.Map(append([]cbor.MapEntry{{Key: cbor.Text("v"), Val: cbor.Int(1)}}, fields...))
}

func dhtEntry(key string, value cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(key), Val: value}
}

func (d *dhtStation) answer(t *testing.T, s *testStation) func(frame.VerifiedRequest) (cbor.Value, bool) {
	return func(r frame.VerifiedRequest) (cbor.Value, bool) {
		d.mu.Lock()
		defer d.mu.Unlock()
		var result cbor.Value
		switch r.Procedure {
		case "_dht.put_record":
			wire, _ := stationArgs(t, r.Procedure, r.Payload).AsBytes()
			if d.refuse != "" {
				result = dhtReply(dhtEntry("result", cbor.Text("refused")), dhtEntry("reason", cbor.Text(d.refuse)))
				break
			}
			verified, err := record.Verify(wire, s.profile, time.Now().UnixMilli())
			if err != nil {
				t.Errorf("station: a put record that does not verify: %v", err)
				return cbor.Value{}, false
			}
			key, _ := record.StorageKey(verified.Record())
			d.byKey[key] = append(d.byKey[key], wire)
			d.byType[verified.Record().Type] = append(d.byType[verified.Record().Type], wire)
			result = dhtReply(dhtEntry("result", cbor.Text("ok")))
		case "_dht.find_record":
			key := keyOf(stationArgs(t, r.Procedure, r.Payload))
			if found := d.byKey[key]; len(found) > 0 {
				result = dhtReply(dhtEntry("result", cbor.Text("record")), dhtEntry("record", cbor.Bytes(found[0])))
			} else {
				result = dhtReply(dhtEntry("result", cbor.Text("not_found")))
			}
		case "_dht.find_records":
			key := keyOf(stationArgs(t, r.Procedure, r.Payload))
			result = dhtReply(dhtEntry("result", cbor.Text("records")), dhtEntry("records", bytesList(append(d.byKey[key], d.extra...))))
		case "_dht.find_records_by_type":
			n, _ := stationArgs(t, r.Procedure, r.Payload).AsInt64()
			result = dhtReply(dhtEntry("result", cbor.Text("records")), dhtEntry("records", bytesList(append(d.byType[record.Type(n)], d.extra...))))
		default:
			return cbor.Value{}, false
		}
		reply, err := frame.SignResult(r, result, nil, s.key)
		return reply, err == nil
	}
}

func keyOf(v cbor.Value) [32]byte {
	b, _ := v.AsBytes()
	var key [32]byte
	copy(key[:], b)
	return key
}

func bytesList(items [][]byte) cbor.Value {
	out := make([]cbor.Value, len(items))
	for i, b := range items {
		out[i] = cbor.Bytes(b)
	}
	return cbor.List(out)
}

// A node record the client signs is put, found by its storage key, and found
// by type, each time as a verified record; a key with nothing stored is
// ErrRecordNotFound.
func TestRecordsArePutAndFoundVerified(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s := linkWithStation(t, p)
			d := &dhtStation{byKey: map[[32]byte][][]byte{}, byType: map[record.Type][][]byte{}}
			s.answerCalls(d.answer(t, s))
			c := newClient(t, p)
			nodeID, _ := c.key.NodeID()
			unsigned, err := record.NewNodeRecord(nodeID, nil, 0, record.NodeRecordOptions{DisplayName: "venus"})
			if err != nil {
				t.Fatalf("NewNodeRecord: %v", err)
			}
			signed, err := record.Sign(unsigned, c.key)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			wire, err := record.Encode(signed)
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			ctx := t.Context()
			if err := link.PutRecord(ctx, wire); err != nil {
				t.Fatalf("PutRecord: %v", err)
			}
			key, _ := record.StorageKey(signed)
			found, err := link.FindRecord(ctx, key)
			if err != nil || found.Record().Type != record.TypeNodeRecord {
				t.Errorf("FindRecord: %v, %v", found.Record().Type, err)
			}
			byType, dropped, err := link.FindRecordsByType(ctx, record.TypeNodeRecord)
			if err != nil || len(byType) != 1 || dropped != 0 {
				t.Errorf("FindRecordsByType: %d records, %d dropped, %v", len(byType), dropped, err)
			}
			if _, err := link.FindRecord(ctx, [32]byte{9}); !errors.Is(err, ErrRecordNotFound) {
				t.Errorf("FindRecord of an empty key: %v, want ErrRecordNotFound", err)
			}
		})
	}
}

// A found record that does not verify is dropped and counted, never handed
// on: here one whose signature byte was changed, and bytes that are not a
// record at all.
func TestARecordThatDoesNotVerifyIsDropped(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	d := &dhtStation{byKey: map[[32]byte][][]byte{}, byType: map[record.Type][][]byte{}}
	s.answerCalls(d.answer(t, s))
	c := newClient(t, profile.PQPure)
	nodeID, _ := c.key.NodeID()
	unsigned, _ := record.NewNodeRecord(nodeID, nil, 0, record.NodeRecordOptions{})
	signed, _ := record.Sign(unsigned, c.key)
	wire, _ := record.Encode(signed)
	if err := link.PutRecord(t.Context(), wire); err != nil {
		t.Fatalf("PutRecord: %v", err)
	}
	tampered := append([]byte{}, wire...)
	tampered[len(tampered)-5] ^= 1
	d.mu.Lock()
	d.extra = [][]byte{tampered, []byte("not a record")}
	d.mu.Unlock()
	records, dropped, err := link.FindRecordsByType(t.Context(), record.TypeNodeRecord)
	if err != nil || len(records) != 1 || dropped != 2 {
		t.Errorf("FindRecordsByType: %d records, %d dropped, %v; want 1 and 2", len(records), dropped, err)
	}
}

// A put the station refuses comes back as a *RecordRefusedError naming the
// custodian's reason (WIRE_1_0.md section 6).
func TestARefusedPutNamesTheCustodiansReason(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	d := &dhtStation{byKey: map[[32]byte][][]byte{}, byType: map[record.Type][][]byte{}, refuse: "lifetime_too_long"}
	s.answerCalls(d.answer(t, s))
	c := newClient(t, profile.PQPure)
	nodeID, _ := c.key.NodeID()
	unsigned, _ := record.NewNodeRecord(nodeID, nil, 0, record.NodeRecordOptions{})
	signed, _ := record.Sign(unsigned, c.key)
	wire, _ := record.Encode(signed)
	err := link.PutRecord(t.Context(), wire)
	var refused *RecordRefusedError
	if !errors.As(err, &refused) || refused.Reason != "lifetime_too_long" || !errors.Is(err, ErrRecordRefused) {
		t.Errorf("PutRecord: %v, want a refusal naming lifetime_too_long", err)
	}
}

// A caller reads a _dht.* reply strictly: an unknown v is
// reply_version_unsupported, and a missing or extra key, or a result the
// procedure never gives, is malformed_reply (WIRE_1_0.md section 6).
func TestADHTReplyIsReadStrictly(t *testing.T) {
	record32 := dhtEntry("record", cbor.Bytes([]byte{1}))
	records := dhtEntry("records", cbor.List(nil))
	ok := map[string]cbor.Value{
		"_dht.put_record ok":         dhtReply(dhtEntry("result", cbor.Text("ok"))),
		"_dht.put_record refused":    dhtReply(dhtEntry("result", cbor.Text("refused")), dhtEntry("reason", cbor.Text("expired"))),
		"_dht.find_record record":    dhtReply(dhtEntry("result", cbor.Text("record")), record32),
		"_dht.find_record not_found": dhtReply(dhtEntry("result", cbor.Text("not_found"))),
		"_dht.find_records records":  dhtReply(dhtEntry("result", cbor.Text("records")), records),
	}
	for name, reply := range ok {
		procedure := name[:strings.Index(name, " ")]
		if _, err := readDHTReply(procedure, reply); err != nil {
			t.Errorf("%s: %v, want it read", name, err)
		}
	}
	for name, c := range map[string]struct {
		procedure string
		reply     cbor.Value
		want      error
	}{
		"v 2":                 {"_dht.put_record", cbor.Map([]cbor.MapEntry{dhtEntry("v", cbor.Int(2)), dhtEntry("result", cbor.Text("ok"))}), ErrReplyVersionUnsupported},
		"no v":                {"_dht.put_record", cbor.Map([]cbor.MapEntry{dhtEntry("result", cbor.Text("ok"))}), ErrMalformedReply},
		"a bare ok":           {"_dht.put_record", cbor.Text("ok"), ErrMalformedReply},
		"an extra key":        {"_dht.put_record", dhtReply(dhtEntry("result", cbor.Text("ok")), dhtEntry("extra", cbor.Int(1))), ErrMalformedReply},
		"refused, no reason":  {"_dht.put_record", dhtReply(dhtEntry("result", cbor.Text("refused"))), ErrMalformedReply},
		"a 65-byte reason":    {"_dht.put_record", dhtReply(dhtEntry("result", cbor.Text("refused")), dhtEntry("reason", cbor.Text(strings.Repeat("r", 65)))), ErrMalformedReply},
		"record, no record":   {"_dht.find_record", dhtReply(dhtEntry("result", cbor.Text("record"))), ErrMalformedReply},
		"not_found, a record": {"_dht.find_record", dhtReply(dhtEntry("result", cbor.Text("not_found")), record32), ErrMalformedReply},
		"records not a list":  {"_dht.find_records", dhtReply(dhtEntry("result", cbor.Text("records")), dhtEntry("records", cbor.Bytes(nil))), ErrMalformedReply},
		"a record in a list":  {"_dht.find_records", dhtReply(dhtEntry("result", cbor.Text("record")), record32), ErrMalformedReply},
		"a result unnamed":    {"_dht.find_records_by_type", dhtReply(dhtEntry("result", cbor.Text("many")), records), ErrMalformedReply},
	} {
		if _, err := readDHTReply(c.procedure, c.reply); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}
