package stationlink

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// Streaming RPC, as macula 12's link does it. Each session has a QUIC stream of
// its own: the caller opens it with a signed STREAM_OPEN naming its mode, the
// station opens one of its own to the provider and relays between them. After
// the open, each side sends frames signed by its own key (the provider's under
// MACULA-PQ-STREAM-V1, the caller's under MACULA-PQ-CALLER-STREAM-V1), each
// numbered from 0 on its side and bound to the open's request hash.
//
// A stream is released, both its QUIC directions finished, on every path: when
// it ends normally, when either side aborts or refuses it, when its inbox is
// over its bound, when its link ends, and when an open or an accepted stream
// fails before a session exists. Each session costs one reader goroutine, and
// on the provider's side one more for its handler, whatever frames it carries.

// The stream bounds, as macula 12.3.0 holds them: an open of at most 1 MiB,
// read within 10 seconds of a stream being opened to the provider, and at most
// 16 MiB of a stream's frames received and not yet read.
var (
	streamOpenBytes = 1024 * 1024
	streamOpenWait  = 10 * time.Second
	streamInbox     = 16 * 1024 * 1024
)

// DefaultStreamDeadline is how long a STREAM_OPEN's deadline lies ahead when
// its StreamCall names none, as macula's default.
const DefaultStreamDeadline = 30 * time.Second

// ErrStreamClosed is a send on a stream this side has ended, or a stream
// released.
var ErrStreamClosed = errors.New("stationlink: the stream is closed on this side")

// StreamError is a stream ended by a STREAM_ERROR: the peer's, signed by it; a
// relay error the connected station signed (Relay); or this side's own abort,
// such as resource_exhausted for an inbox over its bound.
type StreamError struct {
	Code    string
	Message string
	Relay   bool
}

func (e *StreamError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("stationlink: stream error %s: %s", e.Code, e.Message)
	}
	return "stationlink: stream error " + e.Code
}

// StreamEventKind is what a received stream frame was.
type StreamEventKind int

const (
	// StreamData is a chunk.
	StreamData StreamEventKind = iota
	// StreamEnd is the peer's end: Role Send ends its sending only, Both ends
	// the stream.
	StreamEnd
	// StreamReply is the provider's terminal value.
	StreamReply
)

// StreamEvent is one frame the peer sent, verified.
type StreamEvent struct {
	Kind     StreamEventKind
	Encoding frame.StreamEncoding
	Body     cbor.Value
	Role     frame.StreamRole
	Payload  cbor.Value
}

// String names the stream by its side and its open, which shows as
// frame.VerifiedRequest writes one, so the open's credential never shows. It
// reads only what is set when the stream is made.
func (s *Stream) String() string {
	if s == nil {
		return "<nil>"
	}
	side := "provider"
	if s.caller {
		side = "caller"
	}
	return fmt.Sprintf("{%s stream open:%s}", side, s.open)
}

// Format writes it as String does, whatever the verb.
func (s *Stream) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// LogValue writes it as String does, for slog's JSON handler too.
func (s *Stream) LogValue() slog.Value { return slog.StringValue(s.String()) }

// Stream is one streaming session, on either side.
type Stream struct {
	link   *Link
	qs     *quic.Stream
	writer *frameWriter
	open   frame.VerifiedRequest
	caller bool
	// sealing is a sealed stream's keys, nil for a clear one, and plain its
	// opened STREAM_OPEN payload, which a served stream's Request gives.
	sealing *streamSeal
	plain   cbor.Value
	// reopen is a sealed caller stream's call, while it may still reseal
	// once on sealed_refused (StreamCall.Reseal); nil after, or never. A clear
	// caller stream keeps it as the template an adoption reopens under.
	reopen *StreamCall
	// retained is a clear caller stream's ordered copy of what it sent, until
	// the provider's first frame: the actions an adoption replays sealed, and
	// nil once retention ends (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3).
	retained *retainedStream
	// onEnd, when set, runs once when the stream ends: it gives back the
	// session's place and what its inbox held against the node's budgets.
	onEnd  func()
	charge func(n int) bool
	// inboxBound is streamInbox when the stream began.
	inboxBound int

	// sendMu orders this side's frames: each is numbered and written in
	// turn. It is held across the write; mu, which a Recv needs, never is.
	sendMu sync.Mutex

	mu        sync.Mutex
	sendSeq   uint64
	sentEnd   bool // this side sent its last frame, or will send no more
	peerEnded bool // the peer sent its last frame
	inbox     []StreamEvent
	sizes     []int
	held      int
	notify    chan struct{}
	err       error
	done      chan struct{}
	endOnce   sync.Once
	// resetCode is the QUIC code an ungraceful end resets the stream with:
	// 0, or QUIC_CODE_UNKNOWN_FRAME_TYPE after a frame of an unknown type.
	resetCode quic.StreamErrorCode

	// settled is whether a caller's seal report has settled (Report).
	settled bool
}

func newStream(link *Link, qs *quic.Stream, open frame.VerifiedRequest, caller bool) *Stream {
	return &Stream{link: link, qs: qs, writer: &frameWriter{w: qs}, open: open, caller: caller,
		inboxBound: streamInbox, notify: make(chan struct{}, 1), done: make(chan struct{})}
}

// Request is the stream's verified STREAM_OPEN: its caller, procedure, mode and
// payload. On a served stream the payload has no "caller" its sender wrote
// into it, as a CALL's handler sees none: who called is Caller alone.
func (s *Stream) Request() frame.VerifiedRequest {
	// A caller's open is replaced when the stream reseals.
	s.mu.Lock()
	open := s.open
	s.mu.Unlock()
	if s.caller {
		return open
	}
	if s.sealing != nil {
		open.Payload = s.plain
	}
	open.Payload = withoutCaller(open.Payload)
	return open
}

// Done is closed when the stream has ended and been released.
func (s *Stream) Done() <-chan struct{} { return s.done }

// Err is why the stream ended: nil for a normal end, a *StreamError for an
// abort or refusal, or the link's error.
func (s *Stream) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Send sends a raw chunk.
func (s *Stream) Send(body []byte) error {
	return s.send(frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes(body)}, false)
}

// SendValue sends a structured chunk.
func (s *Stream) SendValue(v cbor.Value) error {
	return s.send(frame.StreamDataFields{Encoding: frame.Msgpack, Body: v}, false)
}

// CloseSend ends this side's sending; the peer may still send.
func (s *Stream) CloseSend() error {
	return s.send(frame.StreamEndFields{Role: frame.Send}, true)
}

// Close ends the stream on both sides.
func (s *Stream) Close() error {
	err := s.send(frame.StreamEndFields{Role: frame.Both}, true)
	s.end(nil)
	return err
}

// Reply sends the provider's terminal value and ends the stream.
func (s *Stream) Reply(payload cbor.Value) error {
	err := s.send(frame.StreamReplyFields{Payload: payload}, true)
	s.end(nil)
	return err
}

// Abort ends the stream with a STREAM_ERROR of code and message.
func (s *Stream) Abort(code, message string) error {
	err := s.send(frame.StreamErrorFields{Code: code, Message: message}, true)
	s.end(&StreamError{Code: code, Message: message})
	return err
}

// send signs fields at this side's next seq and writes them; last marks this
// side's last frame, after which its QUIC direction is finished. The write
// happens outside mu, so a send stalled on the network holds up no Recv.
func (s *Stream) send(fields frame.StreamFields, last bool) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.write(fields, last)
}

// write is send under a sendMu the caller already holds, which an adoption's
// replay needs: it writes the copy it took, in order, before any send that was
// waiting on the reopen.
func (s *Stream) write(fields frame.StreamFields, last bool) error {
	s.mu.Lock()
	ended, seq := s.sentEnd, s.sendSeq
	s.mu.Unlock()
	if ended {
		return ErrStreamClosed
	}
	fields = withSeq(fields, seq)
	kept := fields
	if s.sealing != nil {
		sealed, err := s.sealing.sealed(fields, seq)
		if err != nil {
			return err
		}
		fields = sealed
	}
	var signed cbor.Value
	var err error
	if s.caller {
		signed, err = frame.SignCallerStream(fields, s.open, s.link.key)
	} else {
		signed, err = frame.SignProviderStream(fields, s.open, s.link.key)
	}
	if err != nil {
		return err
	}
	encoded := cbor.Encode(signed)
	s.retain(kept, last, len(encoded))
	err = s.writer.write(encoded, MaxFrameBytes)
	s.mu.Lock()
	if err != nil {
		s.sentEnd = true
		s.mu.Unlock()
		return err
	}
	s.sendSeq++
	peerEnded := s.peerEnded
	if last {
		s.sentEnd = true
	}
	s.mu.Unlock()
	if last {
		_ = s.qs.Close()
		if peerEnded {
			go s.end(nil)
		}
	}
	return nil
}

// retainedStream is a clear caller stream's copy of what it has sent, and the
// bytes it holds. It is charged to no inbox: the stream's own bound, streamInbox,
// caps it, and past that retention stops and the copy is dropped.
type retainedStream struct {
	actions []retainedAction
	bytes   int
}

// retainedAction is one action a clear stream sent, kept for an adoption's
// replay: the fields it carried, renumbered from 0 there, and whether it was
// this side's last.
type retainedAction struct {
	fields frame.StreamFields
	last   bool
}

// retain copies fields into the stream's retention while it lives, and ends
// retention at size past its bound (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3).
func (s *Stream) retain(fields frame.StreamFields, last bool, size int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.retained
	if r == nil {
		return
	}
	if r.bytes+size > streamInbox {
		s.retained = nil
		return
	}
	r.actions = append(r.actions, retainedAction{fields: fields, last: last})
	r.bytes += size
}

// firstPeerFrame is a clear stream's retained copy taken at the provider's
// first frame, and the key to adopt when that frame is a sealed_required
// carrying one: any other first frame drops the copy, and so does a refusal
// naming no key or a key of another profile's length, which then surfaces as
// the provider's own refusal.
func (s *Stream) firstPeerFrame(v frame.VerifiedStreamFrame) ([]retainedAction, []byte) {
	s.mu.Lock()
	r := s.retained
	s.retained = nil
	s.mu.Unlock()
	if r == nil {
		return nil, nil
	}
	key, ok := adoptionKey(s.link.profile, v)
	if !ok {
		return nil, nil
	}
	return r.actions, key
}

// adopt reopens a clear stream sealed to the key a sealed_required refusal
// carried, sends the copy first and then what the owner wrote while the reopen
// was in flight - sends wait on sendMu across both - and keeps the session:
// one stream, all of it sealed from here. The replay is numbered from 0 on the
// new session, and carries the copied STREAM_END even though the owner had
// closed its side.
func (s *Stream) adopt(actions []retainedAction, key []byte) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	c := s.reopen
	if c == nil {
		s.end(errNotAdopted)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	s.mu.Lock()
	deadline := s.open.Deadline
	s.mu.Unlock()
	opened, err := s.link.openOn(ctx, *c, key, deadline)
	cancel()
	if err != nil {
		s.end(err)
		return
	}
	s.mu.Lock()
	old := s.qs
	s.qs, s.writer, s.open, s.sealing = opened.qs, &frameWriter{w: opened.qs}, opened.open, opened.sealing
	s.sendSeq, s.sentEnd = 0, false
	s.mu.Unlock()
	abandon(old)
	go s.read(opened.state)
	for _, action := range actions {
		if err := s.write(action.fields, action.last); err != nil {
			s.end(err)
			return
		}
	}
}

// errNotAdopted is a clear stream an adoption had no call to reopen under: a
// stream opened without the call it was opened with.
var errNotAdopted = errors.New("stationlink: this stream keeps no call to reopen under")

func withSeq(fields frame.StreamFields, seq uint64) frame.StreamFields {
	switch f := fields.(type) {
	case frame.StreamDataFields:
		f.Seq = seq
		return f
	case frame.StreamEndFields:
		f.Seq = seq
		return f
	case frame.StreamErrorFields:
		f.Seq = seq
		return f
	case frame.StreamReplyFields:
		f.Seq = seq
		return f
	}
	return fields
}

// Recv is the next frame the peer sent. After the stream ends, once every
// event before it is read, it returns io.EOF for a normal end and the error
// that ended it otherwise.
func (s *Stream) Recv(ctx context.Context) (StreamEvent, error) {
	for {
		s.mu.Lock()
		if len(s.inbox) > 0 {
			event, size := s.inbox[0], s.sizes[0]
			s.inbox, s.sizes = s.inbox[1:], s.sizes[1:]
			s.held -= size
			s.mu.Unlock()
			if s.charge != nil {
				s.charge(-size)
			}
			return event, nil
		}
		finished, err := s.isDone(), s.err
		s.mu.Unlock()
		if finished {
			if err == nil {
				err = io.EOF
			}
			return StreamEvent{}, err
		}
		select {
		case <-s.notify:
		case <-s.done:
		case <-ctx.Done():
			return StreamEvent{}, ctx.Err()
		}
	}
}

func (s *Stream) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// read verifies the peer's frames until the stream ends. It is the stream's
// one reader, the only holder of its verifier state.
func (s *Stream) read(state frame.StreamState) {
	reader := frameReader{r: s.qs}
	for {
		payload, err := reader.read(MaxFrameBytes)
		if err != nil {
			s.readEnded(err)
			return
		}
		next, stop := s.received(payload, state)
		if stop {
			return
		}
		state = next
	}
}

// readEnded ends a stream whose peer direction finished: after the peer's last
// frame that is expected, and before it the stream was lost.
func (s *Stream) readEnded(err error) {
	s.mu.Lock()
	ended := s.peerEnded
	s.mu.Unlock()
	if ended {
		return
	}
	select {
	case <-s.link.done:
		s.end(s.link.Err())
	default:
		s.end(fmt.Errorf("stationlink: the stream was lost before its end: %w", err))
	}
}

// received handles one frame from the peer, and reports whether reading stops.
func (s *Stream) received(payload []byte, state frame.StreamState) (frame.StreamState, bool) {
	verified, state, ok := s.verifiedFrame(payload, state)
	if !ok {
		return state, true
	}
	if actions, key := s.firstPeerFrame(verified); key != nil {
		// The provider refused the clear open sealed_required and named its
		// key: the session reopens sealed, and reads on from there.
		s.adopt(actions, key)
		return state, true
	}
	if s.caller {
		// A frame unsealed returned has opened under the stream's key, or is
		// one a clear stream takes: the report's settle point (Report).
		s.settleOn(verified.FrameType)
	}
	return s.applyFrame(verified, payload, state)
}

// verifiedFrame decodes one frame from the peer and verifies it, unsealing it
// when the stream is sealed. ok is false when the frame was refused and
// reading stops.
func (s *Stream) verifiedFrame(payload []byte, state frame.StreamState) (frame.VerifiedStreamFrame, frame.StreamState, bool) {
	v, err := cbor.Decode(payload)
	if err != nil {
		s.fail("malformed_frame", err)
		return frame.VerifiedStreamFrame{}, state, false
	}
	if unknownOnStream(v) {
		s.mu.Lock()
		s.resetCode = quicCodeUnknownFrameType
		s.mu.Unlock()
		s.end(&StreamError{Code: "unknown_frame_type"})
		return frame.VerifiedStreamFrame{}, state, false
	}
	if _, isRelay := v.Get("relay_error"); isRelay && s.caller {
		relayed, err := frame.VerifyRelayError(v, s.open, s.link.profile, s.link.station.NodeID)
		if err != nil {
			s.fail("malformed_frame", err)
			return frame.VerifiedStreamFrame{}, state, false
		}
		s.peerFinished(&StreamError{Code: relayed.Code, Relay: true})
		return frame.VerifiedStreamFrame{}, state, false
	}
	var verified frame.VerifiedStreamFrame
	if s.caller {
		verified, state, err = frame.VerifyProviderStream(v, state, s.link.profile)
	} else {
		verified, state, err = frame.VerifyCallerStream(v, state, s.link.profile)
	}
	switch {
	case errors.Is(err, frame.ErrEnumUnknown):
		// An enum value this library does not know refuses the frame by
		// name (WIRE_1_0.md section 3.4).
		s.fail("enum_unknown", err)
		return frame.VerifiedStreamFrame{}, state, false
	case err != nil:
		s.fail("malformed_frame", err)
		return frame.VerifiedStreamFrame{}, state, false
	}
	if verified, err = s.unsealed(verified); err != nil {
		s.refuseUnsealed(err)
		return frame.VerifiedStreamFrame{}, state, false
	}
	return verified, state, true
}

// applyFrame is what one verified frame does to the stream; stop reports
// whether reading ends after it.
func (s *Stream) applyFrame(verified frame.VerifiedStreamFrame, payload []byte, state frame.StreamState) (frame.StreamState, bool) {
	switch verified.FrameType {
	case "stream_error":
		s.peerFinished(&StreamError{Code: verified.Code, Message: verified.Message})
		return state, true
	case "stream_reply":
		s.deliver(StreamEvent{Kind: StreamReply, Payload: verified.Payload}, len(payload))
		s.peerFinished(nil)
		return state, true
	case "stream_end":
		s.peerEndReached(verified, payload)
		return state, true
	}
	if !s.deliver(StreamEvent{Kind: StreamData, Encoding: verified.Encoding, Body: verified.Body}, len(payload)) {
		s.fail("resource_exhausted", nil)
		return state, true
	}
	return state, false
}

// peerEndReached is a STREAM_END from the peer: the stream ends once both
// sides have ended, as the end's role says.
func (s *Stream) peerEndReached(verified frame.VerifiedStreamFrame, payload []byte) {
	s.deliver(StreamEvent{Kind: StreamEnd, Role: verified.Role}, len(payload))
	if verified.Role == frame.Both {
		s.peerFinished(nil)
		return
	}
	s.mu.Lock()
	s.peerEnded = true
	mine := s.sentEnd
	s.mu.Unlock()
	if mine {
		s.end(nil)
	}
}

// deliver queues event for Recv, refusing it when it would take the inbox, or
// the node's budget for served streams, past its bound.
func (s *Stream) deliver(event StreamEvent, size int) bool {
	s.mu.Lock()
	if s.held+size > s.inboxBound {
		s.mu.Unlock()
		return false
	}
	if s.charge != nil && !s.charge(size) {
		s.mu.Unlock()
		return false
	}
	s.inbox = append(s.inbox, event)
	s.sizes = append(s.sizes, size)
	s.held += size
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return true
}

// peerFinished ends the stream after the peer's last frame: this side sends
// no more, and err is why it ended, nil for a normal end.
func (s *Stream) peerFinished(err error) {
	s.mu.Lock()
	s.peerEnded = true
	s.mu.Unlock()
	s.end(err)
}

// fail aborts the stream from this side for a fault it found in what the peer
// sent, or an inbox over its bound, telling the peer when it still can.
func (s *Stream) fail(code string, cause error) {
	message := ""
	if cause != nil {
		message = boundedDetail(cause.Error())
	}
	_ = s.send(frame.StreamErrorFields{Code: code, Message: message}, true)
	s.end(&StreamError{Code: code, Message: message})
}

// end releases the stream once: its write direction closed (after this side's
// last frame, gracefully; otherwise reset), its read direction stopped, and
// what it held given back.
func (s *Stream) end(err error) {
	s.endOnce.Do(func() {
		s.mu.Lock()
		if s.err == nil {
			s.err = err
		}
		graceful := s.sentEnd && s.resetCode == 0
		s.sentEnd = true
		resetCode := s.resetCode
		qs := s.qs
		held := s.held
		s.held = 0
		for i := range s.sizes {
			s.sizes[i] = 0
		}
		s.mu.Unlock()
		if graceful {
			_ = qs.Close()
		} else {
			qs.CancelWrite(resetCode)
		}
		qs.CancelRead(resetCode)
		if s.charge != nil && held > 0 {
			s.charge(-held)
		}
		s.link.forgetStream(s)
		if s.onEnd != nil {
			s.onEnd()
		}
		close(s.done)
	})
}
