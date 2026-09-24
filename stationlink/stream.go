package stationlink

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// Stream is one streaming session, on either side.
type Stream struct {
	link   *Link
	qs     *quic.Stream
	writer *frameWriter
	open   frame.VerifiedRequest
	caller bool
	// onEnd, when set, runs once when the stream ends: it gives back the
	// session's place and what its inbox held against the node's budgets.
	onEnd  func()
	charge func(n int) bool
	// inboxBound is streamInbox when the stream began.
	inboxBound int

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
}

func newStream(link *Link, qs *quic.Stream, open frame.VerifiedRequest, caller bool) *Stream {
	return &Stream{link: link, qs: qs, writer: &frameWriter{w: qs}, open: open, caller: caller,
		inboxBound: streamInbox, notify: make(chan struct{}, 1), done: make(chan struct{})}
}

// Request is the stream's verified STREAM_OPEN: its caller, procedure, mode and
// payload.
func (s *Stream) Request() frame.VerifiedRequest { return s.open }

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
// side's last frame, after which its QUIC direction is finished.
func (s *Stream) send(fields frame.StreamFields, last bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sentEnd {
		return ErrStreamClosed
	}
	fields = withSeq(fields, s.sendSeq)
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
	if err := s.writer.write(cbor.Encode(signed), MaxFrameBytes); err != nil {
		s.sentEnd = true
		return err
	}
	s.sendSeq++
	if last {
		s.sentEnd = true
		_ = s.qs.Close()
		if s.peerEnded {
			go s.end(nil)
		}
	}
	return nil
}

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
	v, err := cbor.Decode(payload)
	if err != nil {
		s.fail("malformed_frame", err)
		return state, true
	}
	if _, isRelay := v.Get("relay_error"); isRelay && s.caller {
		relayed, err := frame.VerifyRelayError(v, s.open, s.link.profile, s.link.station.NodeID)
		if err != nil {
			s.fail("malformed_frame", err)
			return state, true
		}
		s.peerFinished(&StreamError{Code: relayed.Code, Relay: true})
		return state, true
	}
	var verified frame.VerifiedStreamFrame
	if s.caller {
		verified, state, err = frame.VerifyProviderStream(v, state, s.link.profile)
	} else {
		verified, state, err = frame.VerifyCallerStream(v, state, s.link.profile)
	}
	if err != nil {
		s.fail("malformed_frame", err)
		return state, true
	}
	switch verified.FrameType {
	case "stream_error":
		s.peerFinished(&StreamError{Code: verified.Code, Message: verified.Message})
		return state, true
	case "stream_reply":
		s.deliver(StreamEvent{Kind: StreamReply, Payload: verified.Payload}, len(payload))
		s.peerFinished(nil)
		return state, true
	case "stream_end":
		s.deliver(StreamEvent{Kind: StreamEnd, Role: verified.Role}, len(payload))
		if verified.Role == frame.Both {
			s.peerFinished(nil)
			return state, true
		}
		s.mu.Lock()
		s.peerEnded = true
		mine := s.sentEnd
		s.mu.Unlock()
		if mine {
			s.end(nil)
		}
		return state, true
	}
	if !s.deliver(StreamEvent{Kind: StreamData, Encoding: verified.Encoding, Body: verified.Body}, len(payload)) {
		s.fail("resource_exhausted", nil)
		return state, true
	}
	return state, false
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
		graceful := s.sentEnd
		s.sentEnd = true
		held := s.held
		s.held = 0
		for i := range s.sizes {
			s.sizes[i] = 0
		}
		s.mu.Unlock()
		if graceful {
			_ = s.qs.Close()
		} else {
			s.qs.CancelWrite(0)
		}
		s.qs.CancelRead(0)
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
