package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"time"

	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/pool"
)

// Node-served content (macula 12.6.0, D27): a node shares content on its own
// ~<node_id>/content_v1 and announces it; a fetch finds the announcements,
// dials each sharer and checks everything against the content id.

// contentOptions bound a fetch as a binding gives them; 0 takes the default.
type contentOptions struct {
	MaxBytes       uint64 `json:"max_bytes"`
	MaxChunks      int    `json:"max_chunks"`
	Parallel       int    `json:"parallel"`
	ChunkTimeoutMs int64  `json:"chunk_timeout_ms"`
}

func parseContentOptions(text string) (pool.ContentOptions, error) {
	var o contentOptions
	if text != "" {
		if err := decodeStrict("content options", text, &o); err != nil {
			return pool.ContentOptions{}, err
		}
	}
	if o.MaxChunks < 0 || o.Parallel < 0 || o.ChunkTimeoutMs < 0 {
		return pool.ContentOptions{}, invalidArgument("a negative content option")
	}
	return pool.ContentOptions{MaxBytes: o.MaxBytes, MaxChunks: o.MaxChunks, Parallel: o.Parallel,
		ChunkTimeout: time.Duration(o.ChunkTimeoutMs) * time.Millisecond}, nil
}

// mcidOf is a 50-byte content id from a buffer the caller owns.
func mcidOf(p *C.uint8_t) (manifest.Mcid, error) {
	var mcid manifest.Mcid
	b, ok := fixed(p, len(mcid))
	if !ok {
		return mcid, invalidArgument("the content id is NULL")
	}
	copy(mcid[:], b)
	return mcid, nil
}

//export macula_pool_share_content
func macula_pool_share_content(h C.uintptr_t, realm32 *C.uint8_t, data *C.uint8_t, dataLen C.size_t, name *C.char,
	timeoutMs C.int64_t, token C.uintptr_t, outMcid *C.uint8_t, errOut **C.char) {
	lp := poolOf(h, errOut)
	if lp == nil {
		return
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return
	}
	defer cancel()
	mcid, err := lp.pool.ShareContent(ctx, realm, goBytes(data, dataLen), goString(name))
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return
	}
	writeFixed(outMcid, mcid[:])
}

//export macula_pool_unshare_content
func macula_pool_unshare_content(h C.uintptr_t, realm32 *C.uint8_t, mcid50 *C.uint8_t, timeoutMs C.int64_t,
	token C.uintptr_t, errOut **C.char) {
	lp := poolOf(h, errOut)
	if lp == nil {
		return
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return
	}
	mcid, err := mcidOf(mcid50)
	if err != nil {
		setErr(errOut, err)
		return
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return
	}
	defer cancel()
	setCtxErr(ctx, errOut, lp.pool.UnshareContent(ctx, realm, mcid))
}

//export macula_pool_get_content
func macula_pool_get_content(h C.uintptr_t, realm32 *C.uint8_t, mcid50 *C.uint8_t, optionsJSON *C.char,
	timeoutMs C.int64_t, token C.uintptr_t, outLen *C.size_t, errOut **C.char) *C.uint8_t {
	*outLen = 0
	lp := poolOf(h, errOut)
	if lp == nil {
		return nil
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	mcid, err := mcidOf(mcid50)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	opts, err := parseContentOptions(goString(optionsJSON))
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
	data, err := lp.pool.GetContent(ctx, realm, mcid, opts)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return nil
	}
	return cBytes(data, outLen)
}
