package stationlink

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/record"
)

// The DHT, as macula 12's facade reaches it: station procedures on the zero
// realm, targeting the connected station, that carry record wire bytes. Every
// record found is verified here before it is handed on (label
// MACULA-PQ-RECORD-V1, the link's profile, its lifetime), and one that does not
// verify is dropped.

var (
	// ErrRecordNotFound is a find_record the station answered not_found.
	ErrRecordNotFound = errors.New("stationlink: no record under that key")
	// ErrUnexpectedReply is a station reply to a DHT call in a shape that call
	// never answers with.
	ErrUnexpectedReply = errors.New("stationlink: the station's reply has an unexpected shape")
)

// PutRecord stores a signed record, as its wire bytes, in the station's DHT.
func (l *Link) PutRecord(ctx context.Context, wire []byte) error {
	result, err := l.Call(ctx, Call{Procedure: "_dht.put_record", Payload: cbor.Bytes(wire)})
	if err != nil {
		return err
	}
	if text, _ := result.AsText(); text != "ok" {
		return fmt.Errorf("%w: put_record answered %v", ErrUnexpectedReply, result)
	}
	return nil
}

// FindRecord is the record stored under key, verified, or ErrRecordNotFound.
// A record that does not verify is refused with Verify's error.
func (l *Link) FindRecord(ctx context.Context, key [32]byte) (record.Verified, error) {
	result, err := l.Call(ctx, Call{Procedure: "_dht.find_record", Payload: keyPayload(key)})
	if err != nil {
		return record.Verified{}, err
	}
	if text, isText := result.AsText(); isText && text == "not_found" {
		return record.Verified{}, ErrRecordNotFound
	}
	wire, isBytes := result.AsBytes()
	if !isBytes {
		return record.Verified{}, fmt.Errorf("%w: find_record answered %v", ErrUnexpectedReply, result)
	}
	return record.Verify(wire, l.profile, time.Now().UnixMilli())
}

// FindRecords is every record stored under key that verifies, and how many
// the station returned that did not.
func (l *Link) FindRecords(ctx context.Context, key [32]byte) ([]record.Verified, int, error) {
	return l.verifiedList(ctx, "_dht.find_records", keyPayload(key))
}

// FindRecordsByType is every record of type t the station holds that
// verifies, and how many it returned that did not.
func (l *Link) FindRecordsByType(ctx context.Context, t record.Type) ([]record.Verified, int, error) {
	return l.verifiedList(ctx, "_dht.find_records_by_type",
		cbor.Map([]cbor.MapEntry{{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(t))}}))
}

func (l *Link) verifiedList(ctx context.Context, procedure string, payload cbor.Value) ([]record.Verified, int, error) {
	result, err := l.Call(ctx, Call{Procedure: procedure, Payload: payload})
	if err != nil {
		return nil, 0, err
	}
	items, isList := result.AsList()
	if !isList {
		return nil, 0, fmt.Errorf("%w: %s answered %v", ErrUnexpectedReply, procedure, result)
	}
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

func keyPayload(key [32]byte) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("key"), Val: cbor.Bytes(key[:])}})
}
