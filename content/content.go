// Package content implements put/get by content-address (§12 of
// plans/PLAN_WIRE_PROTOCOL.md), ported from macula_content_transfer.erl
// via macula-rust's own content.rs. Not a separate wire protocol:
// nothing here is new frame types, just ordinary CALL/RESULT (§6.4)
// against four well-known _content.* procedures, sent on a dedicated
// QUIC stream (connection.Session.OpenDedicatedStream) instead of the
// control stream.
//
// Deliberate v1 simplification (documented per spec §12.2): chunked
// transfers here run strictly sequentially, one _content.put_block /
// _content.get_block in flight at a time on the single dedicated stream
// this package opens — not the reference's parallel multi-lane
// algorithm (round-robin chunks across up to 4 concurrent streams).
// Multi-lane parallelism is a throughput optimization, not a
// correctness requirement: every _content.* call, the MCID scheme, and
// the manifest wire format are identical either way, so this client
// interoperates fully with a station built to serve a parallel-lane
// peer, and lanes can be added later purely as a performance
// improvement with no wire change.
package content

import (
	"context"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
)

// Realm is the reserved sentinel realm for all _content.* calls — 32
// zero bytes, distinct from any real realm (§12.1).
var Realm = make([]byte, 32)

const (
	putBlockProc    = "_content.put_block"
	getBlockProc    = "_content.get_block"
	putManifestProc = "_content.put_manifest"
	getManifestProc = "_content.get_manifest"
)

// blockTimeout matches CONTENT_BLOCK_TIMEOUT_MS.
const blockTimeout = 15 * time.Second

// manifestTimeout matches CONTENT_MANIFEST_TIMEOUT_MS.
const manifestTimeout = 5 * time.Second

// Matches §12.2's retry policy: up to 3 attempts total, 200ms backoff
// between them, only for a BOLT#4 code flagged retryable (§9).
const (
	maxAttempts  = 3
	retryBackoff = 200 * time.Millisecond
)

// RemoteError is returned when the station rejects a _content.* call
// with a BOLT#4 ERROR.
type RemoteError struct {
	Code   uint8
	Name   string
	Detail *string
}

func (e *RemoteError) Error() string {
	return fmt.Sprintf("content: station returned error %d (%s): %v", e.Code, e.Name, e.Detail)
}

// ErrHashMismatch is returned by Put when the station recomputed a
// block's hash and it didn't match the MCID the caller sent (the block
// was not stored), and by Get when a fetched block or reassembled blob
// didn't hash to the MCID it was fetched under — see §12.1's note: a
// station may only be relaying content it doesn't itself store, so its
// answer is never trusted without this client-side check.
type hashMismatchError struct{}

func (hashMismatchError) Error() string { return "content: hash mismatch" }

var ErrHashMismatch error = hashMismatchError{}

// ErrNotFound is returned by Get when the station reports the content
// isn't known to it.
type notFoundError struct{}

func (notFoundError) Error() string { return "content: not found" }

var ErrNotFound error = notFoundError{}

// UnexpectedReplyError is returned when a RESULT arrived but its
// payload wasn't one of the shapes a procedure is documented to return.
type UnexpectedReplyError struct {
	Payload cbor.Value
}

func (e *UnexpectedReplyError) Error() string {
	return fmt.Sprintf("content: unexpected reply shape: %s", e.Payload)
}

// Put stores data, returning the MCID it's now addressable by.
//
// name is attached to the manifest when data is large enough to be
// chunked; a single block (len(data) <= manifest.DefaultChunkSize) is
// addressed purely by content hash and carries no name at all, matching
// macula_content_transfer:put_single_block/3 — name is silently unused
// on that path, not an oversight.
func Put(ctx context.Context, session *connection.Session, data []byte, name string, id identity.KeyPair) (manifest.Mcid, error) {
	stream, err := session.OpenDedicatedStream(ctx)
	if err != nil {
		return manifest.Mcid{}, fmt.Errorf("content: open dedicated stream: %w", err)
	}

	if len(data) <= manifest.DefaultChunkSize {
		mcid := manifest.BlockMcid(data)
		if err := putBlock(stream, mcid, data, id); err != nil {
			return manifest.Mcid{}, err
		}
		return mcid, nil
	}

	opts := manifest.DefaultCreateOptions()
	opts.Name = name
	m, chunks := manifest.Create(data, opts)
	for index, chunk := range chunks {
		chunkMcid, ok := manifest.ChunkMcid(m, index)
		if !ok {
			panic("content: index is in range: it came from iterating manifest.Create's own chunks")
		}
		if err := putBlock(stream, chunkMcid, chunk, id); err != nil {
			return manifest.Mcid{}, err
		}
	}
	if err := putManifestCall(stream, m, id); err != nil {
		return manifest.Mcid{}, err
	}
	return m.Mcid, nil
}

// Get fetches and verifies the content addressed by mcid.
func Get(ctx context.Context, session *connection.Session, mcid manifest.Mcid, id identity.KeyPair) ([]byte, error) {
	stream, err := session.OpenDedicatedStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("content: open dedicated stream: %w", err)
	}

	if !manifest.McidIsChunked(mcid) {
		data, err := getBlock(stream, mcid, id)
		if err != nil {
			return nil, err
		}
		if manifest.BlockMcid(data) != mcid {
			return nil, ErrHashMismatch
		}
		return data, nil
	}

	m, err := getManifestCall(stream, mcid, id)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 0, m.Size)
	for index := 0; index < m.ChunkCount; index++ {
		chunkMcid, ok := manifest.ChunkMcid(m, index)
		if !ok {
			panic("content: index < m.ChunkCount, so m.Chunks[index] exists")
		}
		chunk, err := getBlock(stream, chunkMcid, id)
		if err != nil {
			return nil, err
		}
		if manifest.BlockMcid(chunk) != chunkMcid {
			return nil, ErrHashMismatch
		}
		data = append(data, chunk...)
	}
	if err := manifest.Verify(m, data); err != nil {
		return nil, fmt.Errorf("content: reassembled content failed verification: %w", err)
	}
	return data, nil
}

func putBlock(stream *connection.FrameStream, mcid manifest.Mcid, bytes []byte, id identity.KeyPair) error {
	payload := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])},
		{Key: cbor.Text("payload"), Val: cbor.Bytes(bytes)},
	})
	response, err := callWithRetry(stream, putBlockProc, payload, blockTimeout, id)
	if err != nil {
		return err
	}
	if response.IsError {
		return &RemoteError{Code: response.Code, Name: response.Name, Detail: response.Detail}
	}
	if t, ok := response.Payload.AsText(); ok {
		switch t {
		case "ok":
			return nil
		case "hash_mismatch":
			return ErrHashMismatch
		}
	}
	return &UnexpectedReplyError{Payload: response.Payload}
}

func putManifestCall(stream *connection.FrameStream, m manifest.Manifest, id identity.KeyPair) error {
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("manifest"), Val: manifest.ToWire(m)}})
	response, err := callWithRetry(stream, putManifestProc, payload, manifestTimeout, id)
	if err != nil {
		return err
	}
	if response.IsError {
		return &RemoteError{Code: response.Code, Name: response.Name, Detail: response.Detail}
	}
	if t, ok := response.Payload.AsText(); ok && t == "ok" {
		return nil
	}
	return &UnexpectedReplyError{Payload: response.Payload}
}

func getBlock(stream *connection.FrameStream, mcid manifest.Mcid, id identity.KeyPair) ([]byte, error) {
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}})
	response, err := callWithRetry(stream, getBlockProc, payload, blockTimeout, id)
	if err != nil {
		return nil, err
	}
	if response.IsError {
		return nil, &RemoteError{Code: response.Code, Name: response.Name, Detail: response.Detail}
	}
	if b, ok := response.Payload.AsBytes(); ok {
		return b, nil
	}
	if t, ok := response.Payload.AsText(); ok && t == "not_found" {
		return nil, ErrNotFound
	}
	return nil, &UnexpectedReplyError{Payload: response.Payload}
}

func getManifestCall(stream *connection.FrameStream, mcid manifest.Mcid, id identity.KeyPair) (manifest.Manifest, error) {
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}})
	response, err := callWithRetry(stream, getManifestProc, payload, manifestTimeout, id)
	if err != nil {
		return manifest.Manifest{}, err
	}
	if response.IsError {
		return manifest.Manifest{}, &RemoteError{Code: response.Code, Name: response.Name, Detail: response.Detail}
	}
	if _, ok := response.Payload.AsMap(); ok {
		m, err := manifest.FromWire(response.Payload)
		if err != nil {
			return manifest.Manifest{}, fmt.Errorf("content: decoding the fetched manifest: %w", err)
		}
		return m, nil
	}
	if t, ok := response.Payload.AsText(); ok && t == "not_found" {
		return manifest.Manifest{}, ErrNotFound
	}
	return manifest.Manifest{}, &UnexpectedReplyError{Payload: response.Payload}
}

// callWithRetry sends one _content.* CALL, retrying per §12.2's policy:
// up to maxAttempts total, retryBackoff between them, only when the
// prior attempt's ERROR carries a BOLT#4 code flagged retryable. A
// non-retryable ERROR, or a RESULT (whatever its payload turns out to
// mean to the caller), both return on the first attempt.
func callWithRetry(stream *connection.FrameStream, procedure string, payload cbor.Value, timeout time.Duration, id identity.KeyPair) (frame.CallResponse, error) {
	var (
		response frame.CallResponse
		err      error
	)
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		deadlineMs := time.Now().Add(timeout).UnixMilli()
		response, err = stream.Call(procedure, Realm, payload, deadlineMs, id, timeout)

		shouldRetry := attempt < maxAttempts && err == nil && response.IsError
		if shouldRetry {
			code, ok := bolt4.FromU8(response.Code)
			shouldRetry = ok && code.IsRetryable()
		}
		if !shouldRetry {
			return response, err
		}
		time.Sleep(retryBackoff)
	}
	return response, err
}
