package main

// #include <stdint.h>
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// Serving: a served procedure's calls, or a streaming one's sessions, wait in
// its inbox with a handle each, until macula_served_next takes them
// (CONTRACT.md "Serving and streams").

// pendingCall is a served call waiting for its one answer.
type pendingCall struct {
	once    sync.Once
	answers chan pendingAnswer
}

type pendingAnswer struct {
	payload cbor.Value
	err     error
}

// answer answers the call, once; a second answer is errAnswered.
func (pc *pendingCall) answer(a pendingAnswer) error {
	sent := false
	pc.once.Do(func() {
		pc.answers <- a
		sent = true
	})
	if !sent {
		return errAnswered
	}
	return nil
}

func requestJSON(caller, realm [32]byte, procedure string, payload cbor.Value, deadline time.Time) string {
	text, _ := json.Marshal(map[string]any{
		"caller": hex.EncodeToString(caller[:]), "realm": hex.EncodeToString(realm[:]), "procedure": procedure,
		"payload": payloadToJSON(payload), "deadline_ms": deadline.UnixMilli(),
	})
	return string(text)
}

func streamRequestJSON(s *stationlink.Stream) string {
	open := s.Request()
	return requestJSON(open.Caller, open.Realm, open.Procedure, open.Payload, time.UnixMilli(int64(open.Deadline)))
}

// served is a served procedure with the inbox its calls or sessions wait in.
type served struct {
	owner  *livePool
	served *pool.Served
	box    *inbox
}

// serve serves procedure in realm: each call waits in the inbox as a pending
// call, answered by the binding or, at its deadline, with an error for it.
func serve(lp *livePool, realm [32]byte, procedure string) (*served, error) {
	box := newInbox(waitForRoom)
	handler := func(ctx context.Context, r stationlink.Request) (cbor.Value, error) {
		pending := &pendingCall{answers: make(chan pendingAnswer, 1)}
		ph := newHandle(pending)
		defer release(ph)
		if !box.push(ctx, inboxItem{handle: ph, json: requestJSON(r.Caller, r.Realm, r.Procedure, r.Payload, r.Deadline)}) {
			return cbor.Value{}, errors.New("the call was not taken by its deadline")
		}
		select {
		case a := <-pending.answers:
			return a.payload, a.err
		case <-ctx.Done():
			return cbor.Value{}, errors.New("the call was not answered by its deadline")
		}
	}
	return offer(lp, box, pool.Offer{Realm: realm, Procedure: procedure, Handler: handler})
}

// serveStream serves procedure in realm as a stream of mode: each session
// waits in the inbox as a stream handle, which the binding drives and ends.
func serveStream(lp *livePool, realm [32]byte, procedure string, mode frame.StreamMode) (*served, error) {
	box := newInbox(waitForRoom)
	handler := func(ctx context.Context, s *stationlink.Stream) error {
		sh := newHandle(s)
		if !box.push(ctx, inboxItem{handle: sh, json: streamRequestJSON(s)}) {
			release(sh)
			return errors.New("the session was not taken by its deadline")
		}
		<-s.Done()
		return nil
	}
	return offer(lp, box, pool.Offer{Realm: realm, Procedure: procedure,
		Stream: &stationlink.StreamOffer{Mode: mode, Handler: handler}})
}

func offer(lp *livePool, box *inbox, o pool.Offer) (*served, error) {
	offered, err := lp.pool.Serve(context.Background(), o)
	if err != nil {
		return nil, err
	}
	lp.own(box)
	return &served{owner: lp, served: offered, box: box}, nil
}

// stop withdraws the procedure, and ends what waits untaken: a session is
// aborted and its handle freed; a call is answered at its deadline by its
// handler.
func (s *served) stop() error {
	err := s.served.Stop()
	s.box.close()
	s.owner.disown(s.box)
	for {
		item, state := s.box.next(context.Background())
		if state != inboxItemReady {
			break
		}
		if stream, ok := valueOf[*stationlink.Stream](item.handle); ok {
			_ = stream.Abort("cancelled", "the procedure was withdrawn")
			release(item.handle)
		}
	}
	return err
}

func streamMode(mode C.int32_t) (frame.StreamMode, error) {
	switch m := frame.StreamMode(mode); m {
	case frame.ServerStream, frame.ClientStream, frame.Bidi:
		return m, nil
	}
	return 0, invalidArgument("a stream mode is 0 (server), 1 (client) or 2 (bidi), not %d", mode)
}

//export macula_pool_serve
func macula_pool_serve(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, errOut **C.char) C.uintptr_t {
	lp := poolOf(h, errOut)
	if lp == nil {
		return 0
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	s, err := serve(lp, realm, goString(procedure))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return newHandle(s)
}

//export macula_pool_serve_stream
func macula_pool_serve_stream(h C.uintptr_t, realm32 *C.uint8_t, procedure *C.char, mode C.int32_t,
	errOut **C.char) C.uintptr_t {
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
	s, err := serveStream(lp, realm, goString(procedure), m)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return newHandle(s)
}

func servedOf(h C.uintptr_t, errOut **C.char) *served {
	s, ok := valueOf[*served](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return nil
	}
	return s
}

//export macula_served_next
func macula_served_next(h C.uintptr_t, timeoutMs C.int64_t, token C.uintptr_t, outItem *C.uintptr_t,
	closed *C.int32_t, errOut **C.char) *C.char {
	s := servedOf(h, errOut)
	if s == nil {
		*closed = 0
		return nil
	}
	return takeNext(s.box, token, timeoutMs, outItem, closed, errOut)
}

func answerPending(h C.uintptr_t, a pendingAnswer, errOut **C.char) {
	pending, ok := valueOf[*pendingCall](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return
	}
	setErr(errOut, pending.answer(a))
}

//export macula_pending_reply
func macula_pending_reply(h C.uintptr_t, resultJSON *C.char, errOut **C.char) {
	result, err := payloadFromJSON(goString(resultJSON))
	if err != nil {
		setErr(errOut, err)
		return
	}
	answerPending(h, pendingAnswer{payload: result}, errOut)
}

//export macula_pending_error
func macula_pending_error(h C.uintptr_t, message *C.char, errOut **C.char) {
	answerPending(h, pendingAnswer{err: errors.New(goString(message))}, errOut)
}

//export macula_served_stop
func macula_served_stop(h C.uintptr_t, errOut **C.char) {
	s := servedOf(h, errOut)
	if s == nil {
		return
	}
	setErr(errOut, s.stop())
	release(h)
}
