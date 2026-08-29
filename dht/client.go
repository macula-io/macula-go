package dht

import (
	"fmt"
	"time"

	"github.com/macula-io/macula-go-sdk/bolt4"
	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/connection"
	"github.com/macula-io/macula-go-sdk/identity"
)

// dhtRealm is the all-zero 32-byte realm DHT traffic travels under,
// protocol-internal infrastructure — matches macula.erl's ?DHT_REALM.
var dhtRealm = make([]byte, 32)

// dhtTimeout matches macula.erl's ?DHT_RECORD_TIMEOUT_MS.
const dhtTimeout = 5 * time.Second

const (
	putRecordProc         = "_dht.put_record"
	findRecordProc        = "_dht.find_record"
	findRecordsProc       = "_dht.find_records"
	findRecordsByTypeProc = "_dht.find_records_by_type"
)

// toRPCValue builds the FULL-field-name map macula.erl's put_record/2
// sends as a CALL's args (and find_record/find_records return as a
// RESULT) — distinct from canonicalUnsigned's compact single-letter
// envelope, which exists only to be signed/verified, never sent as such.
func (r Record) toRPCValue() cbor.Value {
	entries := []cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(r.Type))},
		{Key: cbor.Text("key"), Val: cbor.Bytes(r.Key)},
		{Key: cbor.Text("version"), Val: cbor.Bytes(r.Version)},
		{Key: cbor.Text("created_at"), Val: cbor.Int(r.CreatedAt)},
		{Key: cbor.Text("expires_at"), Val: cbor.Int(r.ExpiresAt)},
		{Key: cbor.Text("payload"), Val: r.Payload},
	}
	if len(r.Signature) == 64 {
		entries = append(entries, cbor.MapEntry{Key: cbor.Text("signature"), Val: cbor.Bytes(r.Signature)})
	}
	return cbor.Map(entries)
}

func recordFromRPCValue(v cbor.Value) (Record, error) {
	typV, ok := v.Get("type")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing type")
	}
	typI, ok := typV.AsInt64()
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply has a non-integer type")
	}
	key, ok := bytesField(v, "key")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing key")
	}
	version, ok := bytesField(v, "version")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing version")
	}
	createdV, ok := v.Get("created_at")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing created_at")
	}
	created, ok := createdV.AsInt64()
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply has a non-integer created_at")
	}
	expiresV, ok := v.Get("expires_at")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing expires_at")
	}
	expires, ok := expiresV.AsInt64()
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply has a non-integer expires_at")
	}
	payload, ok := v.Get("payload")
	if !ok {
		return Record{}, fmt.Errorf("dht: record reply missing payload")
	}
	sig, _ := bytesField(v, "signature")
	return Record{
		Type:      uint8(typI),
		Key:       key,
		Version:   version,
		CreatedAt: created,
		ExpiresAt: expires,
		Payload:   payload,
		Signature: sig,
	}, nil
}

func deadlineMs(timeout time.Duration) int64 {
	return time.Now().Add(timeout).UnixMilli()
}

// PutRecord stores a signed record in the mesh DHT. Mirrors
// macula:put_record/2 — the relay validates the signature on receipt.
func PutRecord(session *connection.Session, id identity.KeyPair, rec Record) error {
	resp, err := session.Call(putRecordProc, dhtRealm, rec.toRPCValue(), deadlineMs(dhtTimeout), id, dhtTimeout)
	if err != nil {
		return fmt.Errorf("dht: put_record: %w", err)
	}
	if resp.IsError {
		return fmt.Errorf("dht: put_record failed: %s", bolt4Name(resp.Code))
	}
	return nil
}

// FindRecord fetches one record by its storage key (see ProcedureKey /
// StationEndpointKey). Returns ErrNotFound if none exists — the caller's
// signature should still be checked via Verify before the payload is
// trusted; this function does not verify on the caller's behalf.
func FindRecord(session *connection.Session, id identity.KeyPair, key [32]byte) (Record, error) {
	args := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("key"), Val: cbor.Bytes(key[:])}})
	resp, err := session.Call(findRecordProc, dhtRealm, args, deadlineMs(dhtTimeout), id, dhtTimeout)
	if err != nil {
		return Record{}, fmt.Errorf("dht: find_record: %w", err)
	}
	if resp.IsError {
		return Record{}, fmt.Errorf("dht: find_record failed: %s", bolt4Name(resp.Code))
	}
	if t, ok := resp.Payload.AsText(); ok && t == "not_found" {
		return Record{}, ErrNotFound
	}
	return recordFromRPCValue(resp.Payload)
}

// FindRecords fetches every record stored at key — the full signer-deduped
// multiset (e.g. every procedure_advertisement for one procedure). Each
// record's signature should be verified via Verify before its payload is
// trusted; this function does not verify on the caller's behalf.
func FindRecords(session *connection.Session, id identity.KeyPair, key [32]byte) ([]Record, error) {
	args := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("key"), Val: cbor.Bytes(key[:])}})
	resp, err := session.Call(findRecordsProc, dhtRealm, args, deadlineMs(dhtTimeout), id, dhtTimeout)
	if err != nil {
		return nil, fmt.Errorf("dht: find_records: %w", err)
	}
	if resp.IsError {
		return nil, fmt.Errorf("dht: find_records failed: %s", bolt4Name(resp.Code))
	}
	list, ok := resp.Payload.AsList()
	if !ok {
		return nil, fmt.Errorf("dht: find_records: expected a list reply")
	}
	out := make([]Record, 0, len(list))
	for _, item := range list {
		rec, rerr := recordFromRPCValue(item)
		if rerr != nil {
			continue // skip a malformed entry rather than fail the whole batch
		}
		out = append(out, rec)
	}
	return out, nil
}

// FindRecordsByType returns every record of typ currently visible from the
// station this session is connected to. Coverage depends on that
// station's own view of the DHT. Mirrors macula:find_records_by_type/2.
func FindRecordsByType(session *connection.Session, id identity.KeyPair, typ uint8) ([]Record, error) {
	args := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(typ))}})
	resp, err := session.Call(findRecordsByTypeProc, dhtRealm, args, deadlineMs(dhtTimeout), id, dhtTimeout)
	if err != nil {
		return nil, fmt.Errorf("dht: find_records_by_type: %w", err)
	}
	if resp.IsError {
		return nil, fmt.Errorf("dht: find_records_by_type failed: %s", bolt4Name(resp.Code))
	}
	list, ok := resp.Payload.AsList()
	if !ok {
		return nil, fmt.Errorf("dht: find_records_by_type: expected a list reply")
	}
	out := make([]Record, 0, len(list))
	for _, item := range list {
		rec, rerr := recordFromRPCValue(item)
		if rerr != nil {
			continue
		}
		out = append(out, rec)
	}
	return out, nil
}

func bolt4Name(code uint8) string {
	if bc, ok := bolt4.FromU8(code); ok {
		return bc.Name()
	}
	return fmt.Sprintf("code=%d", code)
}
