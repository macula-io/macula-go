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

// pendingCall is a served call waiting for its one answer. Its first answer
// is taken; an answer after that, or after the call's deadline answered it
// for the binding, is errAnswered (CONTRACT.md "Serving and streams").
type pendingCall struct {
	answers chan pendingAnswer

	mu       sync.Mutex
	answered bool // the binding answered, or the deadline answered for it
	forget   func()
}

type pendingAnswer struct {
	payload cbor.Value
	err     error
}

// answer answers the call, once, unless its deadline answered it first.
func (pc *pendingCall) answer(a pendingAnswer) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.answered {
		return errAnswered
	}
	pc.answered = true
	pc.answers <- a
	return nil
}

// expire answers the call for the binding at its deadline, unless the binding
// answered first; either way the answer given is returned.
func (pc *pendingCall) expire(deadline pendingAnswer) pendingAnswer {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.answered {
		return <-pc.answers
	}
	pc.answered = true
	return deadline
}

// answerPendingHandle answers the pending call h names and ends the handle:
// a pending call's handle lives until its first answer, or until its served
// procedure stops.
func answerPendingHandle(h C.uintptr_t, a pendingAnswer) error {
	pending, ok := valueOf[*pendingCall](h)
	if !ok {
		return errInvalidHandle
	}
	err := pending.answer(a)
	pending.forget()
	release(h)
	return err
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

// served is a served procedure with the inbox its calls or sessions wait in,
// and the pending calls it has handed over and not seen answered.
type served struct {
	owner  *livePool
	served *pool.Served
	box    *inbox

	mu      sync.Mutex
	pending map[C.uintptr_t]*pendingCall
}

func newServed() *served {
	return &served{pending: map[C.uintptr_t]*pendingCall{}}
}

// hold issues a handle for a pending call and keeps it until the call is
// answered or the procedure stops.
func (s *served) hold(pc *pendingCall) C.uintptr_t {
	h := newHandle(pc)
	s.mu.Lock()
	s.pending[h] = pc
	s.mu.Unlock()
	pc.forget = func() {
		s.mu.Lock()
		delete(s.pending, h)
		s.mu.Unlock()
	}
	return h
}

// serve serves procedure in realm: each call waits in the inbox as a pending
// call, answered by the binding or, at its deadline, with an error for it.
func serve(lp *livePool, realm [32]byte, procedure string) (*served, error) {
	s := newServed()
	s.box = newInbox(waitForRoom)
	handler := func(ctx context.Context, r stationlink.Request) (cbor.Value, error) {
		pending := &pendingCall{answers: make(chan pendingAnswer, 1)}
		ph := s.hold(pending)
		if !s.box.push(ctx, inboxItem{handle: ph, json: requestJSON(r.Caller, r.Realm, r.Procedure, r.Payload, r.Deadline)}) {
			a := pending.expire(pendingAnswer{err: errors.New("the call was not taken by its deadline")})
			return a.payload, a.err
		}
		select {
		case a := <-pending.answers:
			return a.payload, a.err
		case <-ctx.Done():
			a := pending.expire(pendingAnswer{err: errors.New("the call was not answered by its deadline")})
			return a.payload, a.err
		}
	}
	return offer(lp, s, pool.Offer{Realm: realm, Procedure: procedure, Handler: handler})
}

// serveStream serves procedure in realm as a stream of mode: each session
// waits in the inbox as a stream handle, which the binding drives and ends.
func serveStream(lp *livePool, realm [32]byte, procedure string, mode frame.StreamMode) (*served, error) {
	s := newServed()
	s.box = newInbox(waitForRoom)
	handler := func(ctx context.Context, st *stationlink.Stream) error {
		sh := newHandle(st)
		if !s.box.push(ctx, inboxItem{handle: sh, json: streamRequestJSON(st)}) {
			release(sh)
			return errors.New("the session was not taken by its deadline")
		}
		<-st.Done()
		return nil
	}
	return offer(lp, s, pool.Offer{Realm: realm, Procedure: procedure,
		Stream: &stationlink.StreamOffer{Mode: mode, Handler: handler}})
}

func offer(lp *livePool, s *served, o pool.Offer) (*served, error) {
	offered, err := lp.pool.Serve(context.Background(), o)
	if err != nil {
		return nil, err
	}
	lp.own(s.box)
	s.owner, s.served = lp, offered
	return s, nil
}

// stop withdraws the procedure, and ends what it still holds: a session not
// taken is aborted and its handle freed, and a call not answered is answered
// with an error and its handle freed.
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
	s.mu.Lock()
	pending := s.pending
	s.pending = map[C.uintptr_t]*pendingCall{}
	s.mu.Unlock()
	for h, pc := range pending {
		_ = pc.answer(pendingAnswer{err: errors.New("the procedure was withdrawn")})
		release(h)
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
	setErr(errOut, answerPendingHandle(h, a))
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
