package stationlink

import (
	"context"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// The refusal codes of a STREAM_OPEN, besides the admission's own, as macula's
// refuse_open sends them.
const (
	codeStreamNotFound     = "not_found"
	codeModeMismatch       = "mode_mismatch"
	codeTooManySessions    = "too_many_sessions"
	codeStreamHandlerError = "error"
)

// acceptStreams takes each stream the station opens to this link, until the
// link ends.
func (l *Link) acceptStreams() {
	for {
		qs, err := l.conn.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go l.incoming(qs)
	}
}

// incoming reads a stream's first frame within streamOpenWait and starts the
// session it opens, or refuses it. A stream that fails before a session exists
// is released before incoming returns: one that does not deliver a STREAM_OPEN
// in time, whose first frame is not one, that does not verify or targets
// another node is dropped without a word, and one the provider refuses is told
// why at seq 0.
func (l *Link) incoming(qs *quic.Stream) {
	_ = qs.SetReadDeadline(time.Now().Add(l.openWait))
	payload, err := frameReader{r: qs}.read(streamOpenBytes)
	_ = qs.SetReadDeadline(time.Time{})
	if err != nil {
		l.count("stream_open_unread")
		abandon(qs)
		return
	}
	v, err := cbor.Decode(payload)
	if err != nil || frameTypeOf(v) != "stream_open" {
		l.count("stream_open_malformed")
		abandon(qs)
		return
	}
	open, err := frame.VerifyRequest(v, l.profile)
	if err != nil {
		l.count("stream_open_unverified")
		abandon(qs)
		return
	}
	if open.Target != l.self {
		l.count("stream_for_another_node")
		abandon(qs)
		return
	}
	state, err := frame.OpenStream(open)
	if err != nil {
		abandon(qs)
		return
	}
	s := newStream(l, qs, open, false)
	offer, code := l.admitStream(open)
	if code != "" {
		s.refuse(code)
		return
	}
	release, full := l.admission.openSession(open.Caller)
	if full {
		s.refuse(codeTooManySessions)
		return
	}
	s.onEnd = release
	s.charge = func(n int) bool { return l.admission.chargeInbox(open.Caller, n) }
	if !l.holdStream(s) {
		release()
		abandon(qs)
		return
	}
	go s.read(state)
	go s.serve(offer.Handler)
}

// admitStream judges an open as macula's link does, in its order: the
// admission (one run per request, the deadline window, its bounds), the
// procedure served here as a stream, and its mode. It returns the offer, or
// the code to refuse with.
func (l *Link) admitStream(open frame.VerifiedRequest) (*StreamOffer, string) {
	verdict := l.admission.admit(open, l.share, time.Now().UnixMilli())
	switch {
	case verdict.refusal != "":
		return nil, verdict.refusal
	case verdict.copy:
		return nil, codeRequestCopy
	}
	l.mu.Lock()
	served := l.served[servedKey{open.Realm, open.Procedure}]
	l.mu.Unlock()
	switch {
	case served == nil || served.offer.Stream == nil:
		return nil, codeStreamNotFound
	case served.offer.Stream.Mode != *open.Mode:
		return nil, codeModeMismatch
	}
	return served.offer.Stream, ""
}

// refuse answers an open with a STREAM_ERROR of code at seq 0 and releases the
// stream.
func (s *Stream) refuse(code string) {
	s.link.count("stream_refused_" + code)
	_ = s.send(frame.StreamErrorFields{Code: code}, true)
	s.end(&StreamError{Code: code})
}

// serve runs the handler for the session, and ends the stream as the handler
// leaves it: closed when it returns nil without ending it, aborted with its
// error or panic.
func (s *Stream) serve(handler StreamHandler) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-s.done
		cancel()
	}()
	err := runStreamHandler(ctx, handler, s)
	switch {
	case err != nil:
		_ = s.Abort(codeStreamHandlerError, boundedDetail(err.Error()))
	default:
		_ = s.Close()
	}
	cancel()
}

func runStreamHandler(ctx context.Context, handler StreamHandler, s *Stream) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%v", r)
		}
	}()
	return handler(ctx, s)
}
