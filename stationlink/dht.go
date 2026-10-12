package stationlink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/record"
)

// The DHT, as wire 1.0 reaches it (macula docs/design/WIRE_1_0.md section 6,
// macula#102): station procedures on the zero realm, targeting the connected
// station, each taking one argument form, {v 1, ...}, and answering
// {v 1, result, ...}. Every record found is verified here as a reader before it
// is handed on (label MACULA-PQ-RECORD-V1, the link's profile, its lifetime),
// and one that does not verify is dropped.

var (
	// ErrRecordNotFound is a find_record the station answered not_found.
	ErrRecordNotFound = errors.New("stationlink: no record under that key")
	// ErrRecordRefused is a put_record the station refused; the refusal is a
	// *RecordRefusedError naming the custodian's reason.
	ErrRecordRefused = errors.New("stationlink: the station refused the record")
	// ErrReplyVersionUnsupported is a _dht.* reply of a v this library does
	// not read (reply_version_unsupported).
	ErrReplyVersionUnsupported = errors.New("stationlink: reply_version_unsupported")
	// ErrMalformedReply is a _dht.* reply without exactly the keys of one of
	// its procedure's results (malformed_reply).
	ErrMalformedReply = errors.New("stationlink: malformed_reply")
)

// RecordRefusedError is a put_record the station refused, with the custodian's
// refusal name (WIRE_1_0.md section 5.2), such as lifetime_too_long.
type RecordRefusedError struct {
	Reason string
}

func (e *RecordRefusedError) Error() string {
	return "stationlink: the station refused the record: " + e.Reason
}

func (e *RecordRefusedError) Unwrap() error { return ErrRecordRefused }

// dhtArgsVersion and dhtReplyVersion are the v of the argument and reply forms
// this library speaks.
const (
	dhtArgsVersion  = 1
	dhtReplyVersion = 1
)

// maxRefusalReasonBytes bounds a refused put's reason.
const maxRefusalReasonBytes = 64

// dhtResults are, per procedure, its results and the keys each carries besides
// v and result, with their rules.
var dhtResults = map[string]map[string]map[string]func(cbor.Value) bool{
	"_dht.put_record": {
		"ok":      {},
		"refused": {"reason": boundedText(maxRefusalReasonBytes)},
	},
	"_dht.find_record": {
		"record":    {"record": isBytes},
		"not_found": {},
	},
	"_dht.find_records":         {"records": {"records": isList}},
	"_dht.find_records_by_type": {"records": {"records": isList}},
}

func isBytes(v cbor.Value) bool { _, ok := v.AsBytes(); return ok }

func isList(v cbor.Value) bool { _, ok := v.AsList(); return ok }

func boundedText(max int) func(cbor.Value) bool {
	return func(v cbor.Value) bool {
		s, ok := v.AsText()
		return ok && s != "" && len(s) <= max
	}
}

// dhtReplyFields is a read _dht.* reply: its result and that result's keys.
type dhtReplyFields struct {
	result string
	fields map[string]cbor.Value
}

// readDHTReply reads a _dht.* reply strictly: a map whose v is 1, else
// ErrReplyVersionUnsupported for another integer v and ErrMalformedReply for
// none; then a result of its procedure carrying exactly that result's keys,
// else ErrMalformedReply.
func readDHTReply(procedure string, reply cbor.Value) (dhtReplyFields, error) {
	entries, isMap := reply.AsMap()
	if !isMap {
		return dhtReplyFields{}, fmt.Errorf("%w: %s answered %v", ErrMalformedReply, procedure, reply)
	}
	fields := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		name, isText := e.Key.AsText()
		if _, seen := fields[name]; !isText || seen {
			return dhtReplyFields{}, fmt.Errorf("%w: %s", ErrMalformedReply, procedure)
		}
		fields[name] = e.Val
	}
	v, hasV := fields["v"]
	version, isInt := v.AsInt64()
	switch {
	case !hasV || !isInt:
		return dhtReplyFields{}, fmt.Errorf("%w: %s answered without v", ErrMalformedReply, procedure)
	case version != dhtReplyVersion:
		return dhtReplyFields{}, fmt.Errorf("%w: %s answered v %d", ErrReplyVersionUnsupported, procedure, version)
	}
	result, _ := fields["result"].AsText()
	rules, known := dhtResults[procedure][result]
	if !known || len(fields) != 2+len(rules) {
		return dhtReplyFields{}, fmt.Errorf("%w: %s answered %v", ErrMalformedReply, procedure, reply)
	}
	for name, rule := range rules {
		if value, has := fields[name]; !has || !rule(value) {
			return dhtReplyFields{}, fmt.Errorf("%w: %s answered %v", ErrMalformedReply, procedure, reply)
		}
	}
	return dhtReplyFields{result: result, fields: fields}, nil
}

// dhtArgs is a _dht.* procedure's one argument form, {v 1, field value}.
func dhtArgs(field string, value cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("v"), Val: cbor.Int(dhtArgsVersion)},
		{Key: cbor.Text(field), Val: value},
	})
}

// dhtCall calls a _dht.* procedure with {v 1, field value} and reads its reply.
func (l *Link) dhtCall(ctx context.Context, procedure, field string, value cbor.Value) (dhtReplyFields, error) {
	reply, err := l.Call(ctx, Call{Procedure: procedure, Payload: dhtArgs(field, value)})
	if err != nil {
		return dhtReplyFields{}, err
	}
	return readDHTReply(procedure, reply)
}

// PutRecord stores a signed record, as its wire bytes, in the station's DHT. A
// refusal is a *RecordRefusedError naming the custodian's reason.
func (l *Link) PutRecord(ctx context.Context, wire []byte) error {
	reply, err := l.dhtCall(ctx, "_dht.put_record", "record", cbor.Bytes(wire))
	if err != nil {
		return err
	}
	if reply.result == "refused" {
		reason, _ := reply.fields["reason"].AsText()
		return &RecordRefusedError{Reason: reason}
	}
	return nil
}

// FindRecord is the record stored under key, verified, or ErrRecordNotFound.
// A record that does not verify is refused with Verify's error.
func (l *Link) FindRecord(ctx context.Context, key [32]byte) (record.Verified, error) {
	reply, err := l.dhtCall(ctx, "_dht.find_record", "key", cbor.Bytes(key[:]))
	if err != nil {
		return record.Verified{}, err
	}
	if reply.result == "not_found" {
		return record.Verified{}, ErrRecordNotFound
	}
	wire, _ := reply.fields["record"].AsBytes()
	return record.Verify(wire, l.profile, time.Now().UnixMilli())
}

// FindRecords is every record stored under key that verifies, and how many
// the station returned that did not.
func (l *Link) FindRecords(ctx context.Context, key [32]byte) ([]record.Verified, int, error) {
	return l.verifiedList(ctx, "_dht.find_records", "key", cbor.Bytes(key[:]))
}

// FindRecordsByType is every record of type t the station holds that
// verifies, and how many it returned that did not.
func (l *Link) FindRecordsByType(ctx context.Context, t record.Type) ([]record.Verified, int, error) {
	return l.verifiedList(ctx, "_dht.find_records_by_type", "type", cbor.Uint64(uint64(t)))
}

func (l *Link) verifiedList(ctx context.Context, procedure, field string, value cbor.Value) ([]record.Verified, int, error) {
	reply, err := l.dhtCall(ctx, procedure, field, value)
	if err != nil {
		return nil, 0, err
	}
	items, _ := reply.fields["records"].AsList()
	now := time.Now().UnixMilli()
	verified := make([]record.Verified, 0, len(items))
	dropped := 0
	for _, item := range items {
		wire, isBytes := item.AsBytes()
		if !isBytes {
			dropped++
			continue
		}
		r, err := record.Verify(wire, l.profile, now)
		if err != nil {
			dropped++
			continue
		}
		verified = append(verified, r)
	}
	return verified, dropped, nil
}
