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
	verdict := l.admission.admit(open, l.share, time.Now().UnixMilli())
	switch {
	case verdict.refusal != "":
		s.refuse(verdict.refusal)
		return
	case verdict.copy:
		s.refuse(codeRequestCopy)
		return
	}
	release, full := l.admission.openSession(open.Caller)
	if full {
		// Before the open is opened, so a caller at its cap costs no
		// decapsulation: in the clear, from the closed set.
		s.refuse(codeTooManySessions)
		return
	}
	offer, code, message := l.servedStream(s, open)
	if code != "" {
		release()
		s.refuseWith(code, message)
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

// servedStream judges an admitted open with room for its session as macula
// 13's link does, in its order: a sealed open opened first, and refused in the
// clear, sealed_refused naming the key this node holds now, when it does not
// open; a clear one refused sealed_required by a procedure past its keyless
// window; then the procedure served here as a stream, its policy and its mode,
// refused sealed once the open was. It returns the offer, or the code and
// message to refuse with. An open that opened leaves s sealed.
func (l *Link) servedStream(s *Stream, open frame.VerifiedRequest) (*StreamOffer, string, string) {
	l.mu.Lock()
	served := l.served[servedKey{open.Realm, open.Procedure}]
	l.mu.Unlock()
	if open.Sealed != nil {
		plain, sealing, refused := l.openRequest(open)
		if sealing == nil {
			return nil, codeSealedRefused, refused
		}
		s.sealing, s.plain = newStreamSeal(sealing, false), plain
	} else if served != nil && !l.clearAllowed(served.offer, time.Now()) {
		return nil, codeSealedRequired, "this procedure takes sealed opens only"
	}
	if served == nil || served.offer.Stream == nil {
		return nil, codeStreamNotFound, ""
	}
	if code := l.authorize(served.offer.Policy, open); code != "" {
		return nil, code, ""
	}
	if served.offer.Stream.Mode != *open.Mode {
		return nil, codeModeMismatch, ""
	}
	return served.offer.Stream, "", ""
}

// refuse answers an open with a STREAM_ERROR of code at seq 0 and releases the
// stream.
func (s *Stream) refuse(code string) {
	s.refuseWith(code, "")
}

// refuseWith is refuse with a message: sealed_refused names the key this node
// holds now in it.
func (s *Stream) refuseWith(code, message string) {
	s.link.count("stream_refused_" + code)
	_ = s.send(frame.StreamErrorFields{Code: code, Message: message}, true)
	s.end(&StreamError{Code: code, Message: message})
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
