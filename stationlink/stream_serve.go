package stationlink

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// refusalDrainWait bounds how long a refused stream keeps reading what the
// caller still sends before it is released: long enough for a clear caller to
// read the refusal and adopt.
const refusalDrainWait = 5 * time.Second

// maxRefusalDrains bounds the refusal drains one link runs at once, a sixth of
// quic-go's default MaxIncomingStreams (100): a flood of refused opens cannot
// hold the incoming streams another caller's session needs.
const maxRefusalDrains = 16

// takeDrain claims one of the link's drain places, and reports whether it got
// one.
func (l *Link) takeDrain() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.drains >= maxRefusalDrains {
		return false
	}
	l.drains++
	return true
}

// giveDrain gives a drain place back.
func (l *Link) giveDrain() {
	l.mu.Lock()
	l.drains--
	l.mu.Unlock()
}

// RefusalDrains is how many refusal drains this link is running now: a refused
// stream a clear caller's adoption may still replay into, reading what that
// caller writes until it adopts.
func (l *Link) RefusalDrains() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.drains
}

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
	open, state, ok := l.readStreamOpen(qs)
	if !ok {
		return
	}
	s := newStream(l, qs, open, false)
	if !l.admitStream(s, open) {
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
		// The session's place is given back when the stream ends, which is at
		// once for most refusals and at the end of a drain for the refusal an
		// adoption replays into: the caller's own session cap bounds those.
		s.onEnd = release
		s.refuseCarrying(code, message, l.refusalExt(code))
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

// readStreamOpen reads a stream's first frame within streamOpenWait and
// returns the STREAM_OPEN it carries and the state it opens. A stream that
// fails before a session exists is released here, without a word.
func (l *Link) readStreamOpen(qs *quic.Stream) (frame.VerifiedRequest, frame.StreamState, bool) {
	_ = qs.SetReadDeadline(time.Now().Add(l.openWait))
	payload, err := frameReader{r: qs}.read(streamOpenBytes)
	_ = qs.SetReadDeadline(time.Time{})
	if err != nil {
		l.count("stream_open_unread")
		abandon(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	v, err := cbor.Decode(payload)
	if err == nil && unknownOnStream(v) {
		l.count("stream_unknown_frame_type")
		abortUnknown(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	if err != nil || frameTypeOf(v) != "stream_open" {
		l.count("stream_open_malformed")
		abandon(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	open, err := frame.VerifyRequest(v, l.profile)
	if err != nil {
		l.count("stream_open_unverified")
		abandon(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	if open.Target != l.self {
		l.count("stream_for_another_node")
		abandon(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	state, err := frame.OpenStream(open)
	if err != nil {
		abandon(qs)
		return frame.VerifiedRequest{}, frame.StreamState{}, false
	}
	return open, state, true
}

// admitStream refuses a stream the admission refuses, and reports whether it
// may go on.
func (l *Link) admitStream(s *Stream, open frame.VerifiedRequest) bool {
	verdict := l.admission.admit(open, l.share, time.Now().UnixMilli())
	switch {
	case verdict.refusal != "":
		s.refuse(verdict.refusal)
		return false
	case verdict.copy:
		s.refuse(codeRequestCopy)
		return false
	}
	return true
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
	s.refuseCarrying(code, message, nil)
}

// refuseCarrying is refuseWith carrying the extensions the refusal's signed tbs
// names: a sealed_required hands the caller the key this node holds now, under
// seal.kem_key (release A, DESIGN_E2E_SEALED_BY_DEFAULT.md section 3). The
// write holds the stream's send mutex, as every write does, so a refusal that
// races an owner's send keeps the two in order.
func (s *Stream) refuseCarrying(code, message string, exts []frame.Ext) {
	s.link.count("stream_refused_" + code)
	s.sendMu.Lock()
	err := s.write(frame.StreamErrorFields{Code: code, Message: message}, true, exts)
	s.sendMu.Unlock()
	refusal := &StreamError{Code: code, Message: message}
	if err != nil || !replayableRefusal(code, exts) || !s.link.takeDrain() {
		// Every other refusal ends at once, and so does this one past the
		// link's drain cap: a refusal never waits for a place to drain in.
		s.end(refusal)
		return
	}
	s.drainRefused(refusal)
}

// replayableRefusal reports whether a refusal is the one a clear caller replays
// its copy into: a sealed_required carrying the provider's key. Only that one
// has a caller that keeps writing until it reads the refusal.
func replayableRefusal(code string, exts []frame.Ext) bool {
	return code == codeSealedRequired && len(exts) > 0
}

// drainRefused reads and discards what the caller still sends and releases the
// stream when its side ends, or at the bounds: streamInbox bytes, or
// refusalDrainWait. A clear caller keeps writing until it reads the refusal -
// a clear stream keeps an ordered copy of what it wrote for exactly that
// (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3) - and a provider that stopped
// reading at once would have the station reset the caller's stream, which
// discards a refusal still in flight to it. Reading on instead keeps both the
// refusal and the caller's writes flowing until the caller adopts. The space it
// holds is the caller's admission session, kept until the stream ends, and one
// of the link's drain places.
func (s *Stream) drainRefused(refusal *StreamError) {
	go func() {
		defer s.link.giveDrain()
		_ = s.qs.SetReadDeadline(time.Now().Add(refusalDrainWait))
		_, _ = io.CopyN(io.Discard, s.qs, int64(streamInbox))
		_ = s.qs.SetReadDeadline(time.Time{})
		s.end(refusal)
	}()
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
