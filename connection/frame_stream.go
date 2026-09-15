package connection

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// readChunkSize is how much is read per Stream.Read call while
// accumulating a frame.
const readChunkSize = 4096

// quicStream is the subset of *quic.Stream FrameStream actually uses —
// narrowed to an interface (rather than the concrete type directly) so
// RecvFrame's io.Reader edge-case handling (see its own comment) can be
// exercised in tests against a fake stream, without a real QUIC
// connection. *quic.Stream satisfies this implicitly; no change needed
// at any real call site.
type quicStream interface {
	io.Reader
	io.Writer
	io.Closer
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	CancelRead(code quic.StreamErrorCode)
	CancelWrite(code quic.StreamErrorCode)
}

// FrameStream sends and receives signed application frames on one QUIC
// stream. The control stream (inside Session) and every dedicated
// stream (content transfer, streaming RPC) opened via
// Session.OpenDedicatedStream / Session.AcceptDedicatedStream are each
// one of these — see plans/PLAN_WIRE_PROTOCOL.md §3, §12, §13.
type FrameStream struct {
	stream   quicStream
	buf      []byte        // bytes read but not yet consumed by a decoded frame
	gate     chan struct{} // holds a token while a frame is written; see sendFrame
	gateInit sync.Once
	// session is the session a dedicated stream was opened or accepted on, for
	// its drop warnings; nil for the control stream.
	session *Session
}

func newFrameStream(stream *quic.Stream) *FrameStream {
	return &FrameStream{stream: stream}
}

// SendFrame encodes and writes v to the stream, waiting as long as it takes
// for a frame another goroutine is writing to finish. Frames sent from several
// goroutines at once are written whole, one after another, without relying on
// the stream to serialize concurrent writes: quic-go documents concurrent
// Write on a stream as not permitted.
func (fs *FrameStream) SendFrame(v cbor.Value) error {
	return fs.sendFrame(v, time.Time{}, 0, nil, nil)
}

var (
	// errWriteLockWait is sendFrame's error when waitUntil passed before the
	// stream was free: nothing was written.
	errWriteLockWait = errors.New("connection: timed out waiting to write")
	// errSendStopped is sendFrame's error when stop closed before the stream
	// was free: nothing was written.
	errSendStopped = errors.New("connection: stopped waiting to write")
)

// ErrMalformedFrame is a frame whose bytes don't decode: a claimed length over
// the frame cap, or CBOR that doesn't parse or doesn't fill its length. A
// control stream that carries one ends its session, and a dedicated stream
// whose first frame is one is refused.
var ErrMalformedFrame = errors.New("connection: malformed frame")

// StreamRefusedCode is the QUIC application error code a refused dedicated
// stream is reset and stopped with, the same code in every macula stack.
const StreamRefusedCode = 2

// StreamProtocolErrorCode is the QUIC application error code an established
// dedicated stream is reset and stopped with when a frame on it doesn't
// decode, the same code in every macula stack.
const StreamProtocolErrorCode = 3

// sendFrame writes v once no other frame is being written on this stream.
// waitUntil bounds that wait (zero waits as long as it takes) and stop ends it
// early (nil never does). writeFor bounds the write itself (zero sets no
// deadline). started, if not nil, is called once the write begins.
//
// Every frame a stream sends passes here, and v is refused before anything is
// written when the decoding rule would refuse it where it arrives, with an
// error wrapping frame.ErrFrameBreaksDecodingRule, or when it is over the frame
// cap, with one wrapping frame.ErrFrameTooLarge.
func (fs *FrameStream) sendFrame(v cbor.Value, waitUntil time.Time, writeFor time.Duration, stop <-chan struct{}, started func()) error {
	if err := frame.CheckFrame(v); err != nil {
		return fmt.Errorf("connection: send frame: %w", err)
	}
	encoded, err := frame.Encode(v)
	if err != nil {
		return fmt.Errorf("connection: encode frame: %w", err)
	}
	if err := fs.takeTurn(waitUntil, stop); err != nil {
		return err
	}
	defer func() { <-fs.gate }()
	if started != nil {
		started()
	}
	if writeFor > 0 {
		_ = fs.stream.SetWriteDeadline(time.Now().Add(writeFor))
		defer func() { _ = fs.stream.SetWriteDeadline(time.Time{}) }()
	}
	if _, err := fs.stream.Write(encoded); err != nil {
		return fmt.Errorf("connection: write frame: %w", err)
	}
	return nil
}

// takeTurn waits until no other frame is being written on this stream, until
// waitUntil (zero waits as long as it takes) or until stop closes.
func (fs *FrameStream) takeTurn(waitUntil time.Time, stop <-chan struct{}) error {
	fs.gateInit.Do(func() { fs.gate = make(chan struct{}, 1) })
	var expired <-chan time.Time
	if !waitUntil.IsZero() {
		timer := time.NewTimer(time.Until(waitUntil))
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case fs.gate <- struct{}{}:
	case <-stop:
		return errSendStopped
	case <-expired:
		return errWriteLockWait
	}
	select {
	case <-stop:
		<-fs.gate
		return errSendStopped
	default:
		return nil
	}
}

// CloseSend closes the send-direction of the underlying QUIC stream —
// a real transport-level FIN, distinct from (and additional to) any
// application-level half-close frame already written over it. The
// receive direction is untouched; RecvFrame keeps working afterward.
//
// Without this, a peer relying on the QUIC transport's own end-of-data
// signal for this stream's send side (rather than only on the parsed
// application frame) never sees one — the underlying stream looks
// like it might still have more coming, even after the application
// has fully agreed the exchange is one-way-done.
func (fs *FrameStream) CloseSend() error {
	return fs.stream.Close()
}

// Abort ends the stream in both directions at once with the application
// error code code: its send side is reset and its receive side stopped, so
// the peer sees the code on both, and nothing more is written or read.
func (fs *FrameStream) Abort(code uint64) {
	fs.stream.CancelWrite(quic.StreamErrorCode(code))
	fs.stream.CancelRead(quic.StreamErrorCode(code))
}

// StopReceiving stops the stream's receive side with the application error
// code code: the peer stops sending, and the stream is released once its send
// side is done too.
func (fs *FrameStream) StopReceiving(code uint64) {
	fs.stream.CancelRead(quic.StreamErrorCode(code))
}

// RecvFrame reads the next complete application frame off the stream,
// using (and updating) fs.buf. deadline bounds the read (Stream.Read
// doesn't take a context directly); a zero deadline means no bound. On a
// dedicated stream, a frame that doesn't decode ends the stream: it is reset
// and stopped with StreamProtocolErrorCode, its buffer is released, and a
// drop warning says so. The error wraps ErrMalformedFrame either way.
func (fs *FrameStream) RecvFrame(deadline time.Time) (cbor.Value, error) {
	v, err := fs.recvFrame(deadline)
	if errors.Is(err, ErrMalformedFrame) && fs.session != nil {
		fs.abortMalformed()
	}
	return v, err
}

// abortMalformed ends a dedicated stream whose bytes no longer decode.
func (fs *FrameStream) abortMalformed() {
	fs.buf = nil
	fs.Abort(StreamProtocolErrorCode)
	fs.warnDrop(dropAbortedStream, reasonMalformed, slog.Attr{})
}

// recvFrame is RecvFrame without ending a dedicated stream whose frame
// doesn't decode, for a stream's first frame, which is refused instead.
func (fs *FrameStream) recvFrame(deadline time.Time) (cbor.Value, error) {
	if err := fs.stream.SetReadDeadline(deadline); err != nil {
		return cbor.Value{}, fmt.Errorf("connection: set read deadline: %w", err)
	}
	chunk := make([]byte, readChunkSize)
	var (
		value cbor.Value
		done  bool
		err   error
	)
	for !done && err == nil {
		value, done, err = fs.decodeOrRead(chunk)
	}
	return value, err
}

// decodeOrRead returns the next complete frame in fs.buf, or, when fs.buf
// holds none yet, reads more of the stream into it and reports not done.
func (fs *FrameStream) decodeOrRead(chunk []byte) (cbor.Value, bool, error) {
	decoded, err := frame.Decode(fs.buf)
	if err != nil {
		return cbor.Value{}, false, fmt.Errorf("%w: %w", ErrMalformedFrame, err)
	}
	if decoded.Complete {
		fs.buf = fs.buf[decoded.Consumed:]
		return decoded.Frame, true, nil
	}
	return cbor.Value{}, false, fs.readInto(chunk)
}

// readInto reads the stream's next bytes into fs.buf through chunk.
func (fs *FrameStream) readInto(chunk []byte) error {
	n, err := fs.stream.Read(chunk)
	fs.buf = append(fs.buf, chunk[:n]...)
	// Per io.Reader's contract, a Read that delivers the stream's
	// final bytes is explicitly permitted to return them together
	// with io.EOF in the same call — quic-go does exactly this
	// when the peer's last STREAM frame carries both the final
	// data and the FIN bit. Those bytes must still be checked for
	// a complete frame (the next decodeOrRead does that) before the
	// error is allowed to end the read; discarding them here turned
	// an already-fully-delivered reply into a bogus EOF error. Only
	// give up once a read truly comes back empty.
	if n == 0 && err != nil {
		return fmt.Errorf("connection: read stream: %w", err)
	}
	return nil
}

// Call sends a signed CALL for procedure on this stream and waits for
// the matching RESULT or ERROR, correlated by call_id.
//
// A RESULT or ERROR counts only when its signature verifies against its
// responded_by or reported_by, it parses, and it carries this call's id; any
// other reply is dropped, with a drop warning on the stream's session, and
// the call keeps waiting. A frame of another type is passed over, which is
// harmless on a dedicated stream (content transfer, streaming RPC), since
// nothing else arrives there. A frame that doesn't decode ends the call with
// an error wrapping ErrMalformedFrame and, on a dedicated stream, aborts the
// stream (see RecvFrame).
func (fs *FrameStream) Call(procedure string, realm []byte, payload cbor.Value, deadlineMs int64, id identity.KeyPair, timeout time.Duration) (frame.CallResponse, error) {
	return fs.callSpec(frame.NewCallSpec(nil, procedure, realm, payload, deadlineMs, id.NodeID()), id, timeout)
}

// CallWithUCAN is Call, additionally attaching ucanToken to the outgoing
// CALL frame — for invoking a UCAN-gated procedure (see package ucan's
// Policy). A procedure that isn't gated ignores the token; one that is
// checks it before ever running its handler (connection.ServeOneCallGated),
// so an invalid/missing token comes back as a BOLT#4 Unauthorized error
// frame, not a Go error from this call.
func (fs *FrameStream) CallWithUCAN(procedure string, realm []byte, payload cbor.Value, deadlineMs int64, id identity.KeyPair, timeout time.Duration, ucanToken []byte) (frame.CallResponse, error) {
	spec := frame.NewCallSpec(nil, procedure, realm, payload, deadlineMs, id.NodeID())
	spec.UcanToken = ucanToken
	return fs.callSpec(spec, id, timeout)
}

func (fs *FrameStream) callSpec(spec frame.CallSpec, id identity.KeyPair, timeout time.Duration) (frame.CallResponse, error) {
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		return frame.CallResponse{}, fmt.Errorf("connection: generate call_id: %w", err)
	}
	spec.CallID = callID
	signed := frame.Sign(frame.Call(spec), id)
	if err := fs.SendFrame(signed); err != nil {
		return frame.CallResponse{}, err
	}

	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return frame.CallResponse{}, fmt.Errorf("connection: call: timed out waiting for a response")
		}
		value, err := fs.RecvFrame(deadline)
		if err != nil {
			return frame.CallResponse{}, err
		}
		if response, ok := fs.replyTo(value, callID); ok {
			return response, nil
		}
	}
}

// replyTo returns value as the reply to the call callID when it is one that
// counts: a RESULT or ERROR whose signature verifies against its responded_by
// or reported_by, that parses, and that carries callID, checked in that
// order. Any other RESULT or ERROR is dropped with a drop warning, and a
// frame of another type is passed over.
func (fs *FrameStream) replyTo(value cbor.Value, callID []byte) (frame.CallResponse, bool) {
	t := frameType(value)
	if t != "result" && t != "error" {
		return frame.CallResponse{}, false
	}
	gotID, hasID := frame.FrameCallID(value)
	reason := signatureReason(value, replySigner(t))
	response, err := frame.ParseCallResponse(value)
	switch {
	case reason != "":
	case !hasID || err != nil:
		reason = reasonMalformed
	case string(gotID) != string(callID):
		reason = reasonUnknownCallID
	default:
		return response, true
	}
	fs.warnDrop(dropReply, reason, callIDDetail(gotID))
	return frame.CallResponse{}, false
}

// StreamReplyCounts reports whether value, a STREAM_REPLY read from this
// stream, is the reply to the stream streamID: signed by the key its
// responded_by names, parsed, and carrying streamID, checked in that order, as
// replyTo checks a RESULT or ERROR. One that isn't is warned about as a
// dropped reply on the stream's session, with its stream_id prefix.
func (fs *FrameStream) StreamReplyCounts(value cbor.Value, streamID []byte) bool {
	reason := streamReplyReason(value, streamID)
	if reason == "" {
		return true
	}
	fs.warnDrop(dropReply, reason, streamIDDetail(bytesField(value, "stream_id")))
	return false
}

// streamReplyReason is why value, a STREAM_REPLY, isn't the reply to the
// stream streamID, or "" when it is.
func streamReplyReason(value cbor.Value, streamID []byte) dropReason {
	if reason := signatureReason(value, "responded_by"); reason != "" {
		return reason
	}
	ev, err := frame.ParseStreamEvent(value)
	if err != nil || ev.Kind != frame.StreamEventReply {
		return reasonMalformed
	}
	if string(ev.StreamID) != string(streamID) {
		return reasonUnknownCallID
	}
	return ""
}

// warnDrop warns about a drop on the session the stream belongs to, if any.
func (fs *FrameStream) warnDrop(kind dropKind, reason dropReason, detail slog.Attr) {
	if fs.session != nil {
		fs.session.warnDrop(kind, reason, detail)
	}
}
