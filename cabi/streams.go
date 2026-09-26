package main

// #include <stdint.h>
// #include <stddef.h>
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// openStream opens a stream of mode on procedure in realm at provider (any
// trusted one when nil), with payload as the open's, living deadline (the
// stationlink default when 0).
func openStream(ctx context.Context, p *pool.Pool, realm [32]byte, procedure string, mode frame.StreamMode,
	payloadJSON string, provider *[32]byte, deadline time.Duration) (*stationlink.Stream, error) {
	payload, err := payloadFromJSON(payloadJSON)
	if err != nil {
		return nil, err
	}
	c := pool.StreamCall{Realm: realm, Procedure: procedure, Mode: mode, Payload: payload, Deadline: deadline}
	if provider != nil {
		c.Provider = *provider
	}
	return p.OpenStream(ctx, c)
}

// recvJSON is the peer's next frame as the ABI returns it. The stream's own
// end is a frame (eof, or error for a STREAM_ERROR), not an error; only a
// wait that ran out or was cancelled is.
func recvJSON(ctx context.Context, s *stationlink.Stream) (string, error) {
	event, err := s.Recv(ctx)
	var out map[string]any
	var streamErr *stationlink.StreamError
	switch {
	case err == nil:
		out = streamEventJSON(event)
	case errors.Is(err, io.EOF):
		out = map[string]any{"kind": "eof"}
	case errors.As(err, &streamErr):
		out = map[string]any{"kind": "error", "code": streamErr.Code, "message": streamErr.Message,
			"relay": flag(streamErr.Relay)}
	default:
		return "", err
	}
	text, _ := json.Marshal(out)
	return string(text), nil
}

func streamEventJSON(e stationlink.StreamEvent) map[string]any {
	switch e.Kind {
	case stationlink.StreamEnd:
		return map[string]any{"kind": "end", "role": e.Role.Name()}
	case stationlink.StreamReply:
		return map[string]any{"kind": "reply", "payload": payloadToJSON(e.Payload)}
	}
	return map[string]any{"kind": "data", "encoding": e.Encoding.Name(), "body": payloadToJSON(e.Body)}
}

func streamOf(h C.uintptr_t, errOut **C.char) *stationlink.Stream {
	s, ok := valueOf[*stationlink.Stream](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return nil
	}
	return s
}

//export macula_pool_open_stream
func macula_pool_open_stream(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, mode C.int32_t, payloadJSON *C.char,
	provider32 *C.uint8_t, deadlineMs C.int64_t, timeoutMs C.int64_t, token C.uintptr_t, errOut **C.char) C.uintptr_t {
	lp := poolOf(h, errOut)
	if lp == nil {
		return 0
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	m, err := streamMode(mode)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	if deadlineMs < 0 {
		setErr(errOut, invalidArgument("a negative deadline_ms"))
		return 0
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	defer cancel()
	s, err := openStream(ctx, lp.pool, realm, goString(procedure), m, goString(payloadJSON), optionalID(provider32),
		time.Duration(deadlineMs)*time.Millisecond)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return 0
	}
	return newHandle(s)
}

//export macula_stream_request
func macula_stream_request(h C.uintptr_t, errOut **C.char) *C.char {
	s := streamOf(h, errOut)
	if s == nil {
		return nil
	}
	return cString(streamRequestJSON(s))
}

//export macula_stream_send_bytes
func macula_stream_send_bytes(h C.uintptr_t, data *C.uint8_t, dataLen C.size_t, errOut **C.char) {
	if s := streamOf(h, errOut); s != nil {
		setErr(errOut, s.Send(goBytes(data, dataLen)))
	}
}

//export macula_stream_send_json
func macula_stream_send_json(h C.uintptr_t, valueJSON *C.char, errOut **C.char) {
	s := streamOf(h, errOut)
	if s == nil {
		return
	}
	v, err := payloadFromJSON(goString(valueJSON))
	if err != nil {
		setErr(errOut, err)
		return
	}
	setErr(errOut, s.SendValue(v))
}

//export macula_stream_close_send
func macula_stream_close_send(h C.uintptr_t, errOut **C.char) {
	if s := streamOf(h, errOut); s != nil {
		setErr(errOut, s.CloseSend())
	}
}

//export macula_stream_reply
func macula_stream_reply(h C.uintptr_t, payloadJSON *C.char, errOut **C.char) {
	s := streamOf(h, errOut)
	if s == nil {
		return
	}
	v, err := payloadFromJSON(goString(payloadJSON))
	if err != nil {
		setErr(errOut, err)
		return
	}
	setErr(errOut, s.Reply(v))
}

//export macula_stream_abort
func macula_stream_abort(h C.uintptr_t, code, message *C.char, errOut **C.char) {
	if s := streamOf(h, errOut); s != nil {
		setErr(errOut, s.Abort(goString(code), goString(message)))
	}
}

//export macula_stream_close
func macula_stream_close(h C.uintptr_t, errOut **C.char) {
	if s := streamOf(h, errOut); s != nil {
		setErr(errOut, s.Close())
	}
}

//export macula_stream_recv
func macula_stream_recv(h C.uintptr_t, timeoutMs C.int64_t, token C.uintptr_t, errOut **C.char) *C.char {
	s := streamOf(h, errOut)
	if s == nil {
		return nil
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	defer cancel()
	out, err := recvJSON(ctx, s)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return nil
	}
	return cString(out)
}

//export macula_stream_free
func macula_stream_free(h C.uintptr_t) {
	s, ok := valueOf[*stationlink.Stream](h)
	if !ok {
		return
	}
	select {
	case <-s.Done():
	default:
		_ = s.Abort("cancelled", "the stream was released")
	}
	release(h)
}
