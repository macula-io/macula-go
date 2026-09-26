package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/record"
)

// recordJSON is a verified record: its type, signer's key id, times, payload
// and wire bytes.
func recordJSON(v record.Verified) map[string]any {
	r := v.Record()
	wire, _ := record.Encode(r)
	return map[string]any{
		"type": uint8(r.Type), "key_id": hex.EncodeToString(r.KeyID[:]), "created_at": r.CreatedAt,
		"expires_at": r.ExpiresAt, "payload": payloadToJSON(r.Payload),
		"wire": map[string]string{bytesKey: base64.StdEncoding.EncodeToString(wire)},
	}
}

func recordsJSON(found []record.Verified, dropped int) string {
	out := make([]map[string]any, len(found))
	for i, v := range found {
		out[i] = recordJSON(v)
	}
	text, _ := json.Marshal(map[string]any{"records": out, "dropped": dropped})
	return string(text)
}

func findRecord(ctx context.Context, p *pool.Pool, key [32]byte) (string, error) {
	found, err := p.FindRecord(ctx, key)
	if err != nil {
		return "", err
	}
	text, _ := json.Marshal(recordJSON(found))
	return string(text), nil
}

func findRecords(ctx context.Context, p *pool.Pool, key [32]byte) (string, error) {
	found, dropped, err := p.FindRecords(ctx, key)
	if err != nil {
		return "", err
	}
	return recordsJSON(found, dropped), nil
}

func findRecordsByType(ctx context.Context, p *pool.Pool, recordType int32) (string, error) {
	if recordType < 1 || recordType > 255 {
		return "", invalidArgument("a record type is 1 to 255, not %d", recordType)
	}
	found, dropped, err := p.FindRecordsByType(ctx, record.Type(recordType))
	if err != nil {
		return "", err
	}
	return recordsJSON(found, dropped), nil
}

// lookup runs a DHT lookup export: the pool, a context bounded by its
// timeout and token, and the JSON result or the error.
func lookup(h, token C.uintptr_t, timeoutMs C.int64_t, errOut **C.char,
	find func(ctx context.Context, p *pool.Pool) (string, error)) *C.char {
	lp := poolOf(h, errOut)
	if lp == nil {
		return nil
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	defer cancel()
	out, err := find(ctx, lp.pool)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return nil
	}
	return cString(out)
}

func keyArg(key32 *C.uint8_t, errOut **C.char) ([32]byte, bool) {
	key, ok := id32(key32)
	if !ok {
		setErr(errOut, invalidArgument("the record key is NULL"))
	}
	return key, ok
}

//export macula_pool_find_record
func macula_pool_find_record(h C.uintptr_t, key32 *C.uint8_t, timeoutMs C.int64_t, token C.uintptr_t,
	errOut **C.char) *C.char {
	key, ok := keyArg(key32, errOut)
	if !ok {
		return nil
	}
	return lookup(h, token, timeoutMs, errOut, func(ctx context.Context, p *pool.Pool) (string, error) {
		return findRecord(ctx, p, key)
	})
}

//export macula_pool_find_records
func macula_pool_find_records(h C.uintptr_t, key32 *C.uint8_t, timeoutMs C.int64_t, token C.uintptr_t,
	errOut **C.char) *C.char {
	key, ok := keyArg(key32, errOut)
	if !ok {
		return nil
	}
	return lookup(h, token, timeoutMs, errOut, func(ctx context.Context, p *pool.Pool) (string, error) {
		return findRecords(ctx, p, key)
	})
}

//export macula_pool_find_records_by_type
func macula_pool_find_records_by_type(h C.uintptr_t, recordType C.int32_t, timeoutMs C.int64_t, token C.uintptr_t,
	errOut **C.char) *C.char {
	return lookup(h, token, timeoutMs, errOut, func(ctx context.Context, p *pool.Pool) (string, error) {
		return findRecordsByType(ctx, p, int32(recordType))
	})
}

//export macula_pool_put_record
func macula_pool_put_record(h C.uintptr_t, wire *C.uint8_t, wireLen C.size_t, timeoutMs C.int64_t, token C.uintptr_t,
	errOut **C.char) {
	lp := poolOf(h, errOut)
	if lp == nil {
		return
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return
	}
	defer cancel()
	setCtxErr(ctx, errOut, lp.pool.PutRecord(ctx, goBytes(wire, wireLen)))
}
