package main

// #include <stdint.h>
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/macula-io/macula-go/pool"
)

// call calls procedure in realm at provider (any trusted one when nil) and
// returns its result's JSON. timeout bounds the call on the wire too: it is
// the CALL's deadline.
func call(ctx context.Context, p *pool.Pool, realm [32]byte, procedure, payloadJSON string, provider *[32]byte,
	timeout time.Duration) (string, error) {
	payload, err := payloadFromJSON(payloadJSON)
	if err != nil {
		return "", err
	}
	c := pool.Call{Realm: realm, Procedure: procedure, Payload: payload, Timeout: timeout}
	if provider != nil {
		c.Provider = *provider
	}
	result, err := p.Call(ctx, c)
	if err != nil {
		return "", err
	}
	return string(payloadToJSON(result)), nil
}

// providers is JSON of the procedure's trusted providers, freshest first.
func providers(ctx context.Context, p *pool.Pool, realm [32]byte, procedure string) (string, error) {
	found, err := p.Providers(ctx, realm, procedure)
	if err != nil {
		return "", err
	}
	type entry struct {
		Node    string `json:"node"`
		Station string `json:"station"`
	}
	out := make([]entry, len(found))
	for i, pr := range found {
		out[i] = entry{Node: hex.EncodeToString(pr.Node[:]), Station: hex.EncodeToString(pr.Station[:])}
	}
	text, _ := json.Marshal(out)
	return string(text), nil
}

// realmOf is a required 32-byte realm id.
func realmOf(p *C.uint8_t) ([32]byte, error) {
	realm, ok := id32(p)
	if !ok {
		return realm, invalidArgument("the realm id is NULL")
	}
	return realm, nil
}

// optionalID is a 32-byte id, or nil for NULL.
func optionalID(p *C.uint8_t) *[32]byte {
	id, ok := id32(p)
	if !ok {
		return nil
	}
	return &id
}

//export macula_pool_call
func macula_pool_call(h C.uintptr_t, realm32 *C.uint8_t, procedure, payloadJSON *C.char, provider32 *C.uint8_t,
	timeoutMs C.int64_t, token C.uintptr_t, errOut **C.char) *C.char {
	lp := poolOf(h, errOut)
	if lp == nil {
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	defer cancel()
	result, err := call(ctx, lp.pool, realm, goString(procedure), goString(payloadJSON), optionalID(provider32),
		time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return nil
	}
	return cString(result)
}

//export macula_pool_providers
func macula_pool_providers(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, timeoutMs C.int64_t,
	token C.uintptr_t, errOut **C.char) *C.char {
	lp := poolOf(h, errOut)
	if lp == nil {
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	defer cancel()
	out, err := providers(ctx, lp.pool, realm, goString(procedure))
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return nil
	}
	return cString(out)
}
