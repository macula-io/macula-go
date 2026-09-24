package stationlink

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

// dhtStation answers the station's _dht.* procedures from memory, storing
// record wire bytes by their storage key, as a station's DHT slot does.
type dhtStation struct {
	mu     sync.Mutex
	byKey  map[[32]byte][][]byte
	byType map[record.Type][][]byte
	extra  [][]byte // returned beside the stored records, verified or not
}

func (d *dhtStation) answer(t *testing.T, s *testStation) func(frame.VerifiedRequest) (cbor.Value, bool) {
	return func(r frame.VerifiedRequest) (cbor.Value, bool) {
		d.mu.Lock()
		defer d.mu.Unlock()
		var result cbor.Value
		switch r.Procedure {
		case "_dht.put_record":
			wire, _ := r.Payload.AsBytes()
			verified, err := record.Verify(wire, s.profile, time.Now().UnixMilli())
			if err != nil {
				t.Errorf("station: a put record that does not verify: %v", err)
				return cbor.Value{}, false
			}
			key, _ := record.StorageKey(verified.Record())
			d.byKey[key] = append(d.byKey[key], wire)
			d.byType[verified.Record().Type] = append(d.byType[verified.Record().Type], wire)
			result = cbor.Text("ok")
		case "_dht.find_record":
			key := keyOf(r.Payload)
			if found := d.byKey[key]; len(found) > 0 {
				result = cbor.Bytes(found[0])
			} else {
				result = cbor.Text("not_found")
			}
		case "_dht.find_records":
			result = bytesList(append(d.byKey[keyOf(r.Payload)], d.extra...))
		case "_dht.find_records_by_type":
			typeValue, _ := r.Payload.Get("type")
			n, _ := typeValue.AsInt64()
			result = bytesList(append(d.byType[record.Type(n)], d.extra...))
		default:
			return cbor.Value{}, false
		}
		reply, err := frame.SignResult(r, result, nil, s.key)
		return reply, err == nil
	}
}

func keyOf(payload cbor.Value) [32]byte {
	v, _ := payload.Get("key")
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
