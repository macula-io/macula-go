// Package stream implements general-purpose streaming RPC, both the
// caller/consumer role (§13.1) and the provider role (§13.2) of
// plans/PLAN_WIRE_PROTOCOL.md, ported from macula_stream_sink.erl via
// macula-rust's own stream.rs. Like content transfer (package
// content), this is not a separate wire mechanism: it runs the frame
// types built in frame/stream.go over a dedicated QUIC stream, opened
// via connection.Session.OpenDedicatedStream rather than the control
// stream.
//
// Caller/consumer usage, matching the reference's own pattern:
//  1. Open sends STREAM_OPEN and returns a handle once the frame is on
//     the wire — there's no open-time acknowledgement to wait for; the
//     provider starts reacting to it directly.
//  2. Drive a receive loop with Recv until StreamItemEOF or an error.
//  3. For ClientStream/Bidi modes wanting a result: SendData each chunk
//     in order, CloseSend when done, then AwaitReply.
//  4. Non-normal termination must call Abort, not just drop the handle
//     — the peer's only signal to tell a cancellation/failure apart
//     from a dropped connection (§13.1, point 4).
//
// Provider usage:
//  1. connection.Session.Advertise once per procedure this session will
//     answer.
//  2. Loop on Accept, which blocks for the next inbound STREAM_OPEN and
//     hands back a ready-to-use handle plus the parsed
//     frame.StreamOpenInfo (check its Procedure — a single connection's
//     dedicated streams aren't partitioned by which procedure they're
//     for, so a session that's advertised more than one needs this to
//     route). Accept only hands back a STREAM_OPEN whose signature
//     verified against its caller; turn down one you won't serve with
//     Refuse.
//  3. Drive it exactly like the caller side, from the opposite chair:
//     ServerStream mode pushes with SendData/CloseSend; ClientStream
//     mode drains with Recv and finishes with SendReply.
package stream

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// Handle is one dedicated-stream streaming-RPC exchange, held by both
// the caller (via Open) and the provider (via Accept) — a stream's wire
// vocabulary (STREAM_DATA/END/ERROR/REPLY) is symmetric regardless of
// which side opened it, so SendData/Recv/CloseSend/Abort all mean the
// same thing either way. SendReply is the one provider-only addition.
type Handle struct {
	fs       frameStream
	StreamID []byte
	Mode     frame.StreamMode
	seqOut   uint64
}

// frameStream is what a Handle needs from its dedicated stream: a
// connection.FrameStream, or a test's in-memory stand-in.
type frameStream interface {
	SendFrame(v cbor.Value) error
	RecvFrame(deadline time.Time) (cbor.Value, error)
	CloseSend() error
	Abort(code uint64)
	StopReceiving(code uint64)
	StreamReplyVerifies(v cbor.Value) bool
}

// Open opens a dedicated stream on session's connection and sends a
// signed STREAM_OPEN. Fire-and-forget at the wire level — no reply is
// expected here; drive Recv (for ServerStream/Bidi) or SendData (for
// ClientStream/Bidi) next, depending on mode.
func Open(ctx context.Context, session *connection.Session, procedure string, realm []byte, mode frame.StreamMode, args cbor.Value, deadlineMs int64, id identity.KeyPair) (*Handle, error) {
	fs, err := session.OpenDedicatedStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("stream: open dedicated stream: %w", err)
	}
	streamID := make([]byte, 16)
	if _, err := rand.Read(streamID); err != nil {
		return nil, fmt.Errorf("stream: generate stream_id: %w", err)
	}
	spec := frame.NewStreamOpenSpec(streamID, procedure, realm, mode, args, deadlineMs, id.NodeID())
	signed := frame.Sign(frame.StreamOpen(spec), id)
	if err := fs.SendFrame(signed); err != nil {
		return nil, fmt.Errorf("stream: send stream_open: %w", err)
	}
	return &Handle{fs: fs, StreamID: streamID, Mode: mode}, nil
}

// Accept is the provider role: block for the next inbound STREAM_OPEN
// on session's connection, bounded by timeout. Only ever succeeds after
// connection.Session.Advertise has registered at least one procedure —
// otherwise the station has nothing to route here. Returns the
// ready-to-use handle alongside the parsed frame.StreamOpenInfo (check
// its Procedure if this session advertised more than one).
//
// Accept has no procedure lookup or policy of its own. Every STREAM_OPEN it
// returns is one whose signature verified against its caller: a dedicated
// stream whose first frame isn't that is refused before Accept sees it (see
// connection.Session.AcceptStreamOpen). Deciding whether to serve a returned
// stream is the provider's, and a provider that won't serve one turns it
// down with Handle.Refuse. When the STREAM_OPEN's args are a map, they carry
// the verified caller under "caller".
func Accept(session *connection.Session, timeout time.Duration) (*Handle, frame.StreamOpenInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	fs, open, err := session.AcceptStreamOpen(ctx, timeout)
	if err != nil {
		return nil, frame.StreamOpenInfo{}, fmt.Errorf("stream: accept: %w", err)
	}
	return &Handle{fs: fs, StreamID: open.StreamID, Mode: open.Mode}, open, nil
}

// SendReply is the provider role: send the terminal STREAM_REPLY a
// ClientStream/Bidi caller's own AwaitReply is waiting on, once this
// side has fully consumed and verified whatever the caller streamed.
func (h *Handle) SendReply(payload cbor.Value, id identity.KeyPair) error {
	spec := frame.NewStreamReplySpec(h.StreamID, payload, id.NodeID())
	return h.fs.SendFrame(frame.Sign(frame.StreamReply(spec), id))
}

// SendData sends one chunk. seq is tracked internally, starting at 0
// and incrementing per call — matches the reference's seq_out counter
// (a sanity/debugging signal, not used for reordering: frames arrive in
// order on a single QUIC stream by construction).
func (h *Handle) SendData(encoding frame.StreamEncoding, body cbor.Value, id identity.KeyPair) error {
	spec := frame.NewStreamDataSpec(h.StreamID, h.seqOut, encoding, body, id.NodeID())
	h.seqOut++
	return h.fs.SendFrame(frame.Sign(frame.StreamData(spec), id))
}

// CloseSend half-closes: signal this side is done sending, both at the
// application level (a signed STREAM_END frame the peer's relay logic
// acts on) and at the QUIC transport level (a real FIN on this
// stream's send side) — the two were previously out of sync, leaving
// the transport thinking more data might still come after the
// application had already agreed the exchange was one-way-done. For
// ClientStream/Bidi modes, follow with AwaitReply.
func (h *Handle) CloseSend(id identity.KeyPair) error {
	spec := frame.NewStreamEndSpec(h.StreamID, frame.Send, id.NodeID())
	if err := h.fs.SendFrame(frame.Sign(frame.StreamEnd(spec), id)); err != nil {
		return err
	}
	return h.fs.CloseSend()
}

// Item is one value Recv hands back: a chunk, or a clean end-of-stream.
type Item struct {
	IsEOF    bool
	Seq      uint64
	Encoding frame.StreamEncoding
	Body     cbor.Value
}

// ErrPeerAborted is returned by Recv/AwaitReply when the peer sent an
// explicit STREAM_ERROR abort. Use errors.As to recover the code and
// message.
type ErrPeerAborted struct {
	Code    string
	Message string
}

func (e *ErrPeerAborted) Error() string {
	return fmt.Sprintf("stream: peer aborted the stream: %s (%s)", e.Code, e.Message)
}

// ErrStreamIDMismatch is returned when a frame for a *different*
// stream_id arrived on this stream — never expected on a dedicated
// stream with a well-behaved peer, surfaced distinctly rather than
// silently accepted.
var ErrStreamIDMismatch = errors.New("stream: received a frame for a different stream_id")

// ErrUnexpectedFrame is returned when a frame arrived that isn't valid
// in the context this call is waiting in — e.g. Recv got a
// STREAM_REPLY (only AwaitReply expects one), or AwaitReply got a
// STREAM_DATA/STREAM_END before any reply.
var ErrUnexpectedFrame = errors.New("stream: received a frame not valid in this context")

// Recv receives the next chunk or end-of-stream, bounded by timeout. A frame
// that doesn't decode aborts the stream (see connection.FrameStream.RecvFrame).
//
// STREAM_DATA, STREAM_END and STREAM_ERROR have no signer field in macula's
// frame spec. Go fills one and signs them, but a receiver can't rely on
// either, so what Recv hands back isn't checked against a key: it is taken as
// coming from the peer of the dedicated stream its verified STREAM_OPEN set
// up.
func (h *Handle) Recv(timeout time.Duration) (Item, error) {
	value, err := h.fs.RecvFrame(time.Now().Add(timeout))
	if err != nil {
		return Item{}, fmt.Errorf("stream: recv: %w", err)
	}
	ev, err := frame.ParseStreamEvent(value)
	if err != nil {
		return Item{}, fmt.Errorf("stream: recv: %w", err)
	}
	switch ev.Kind {
	case frame.StreamEventData:
		if err := h.checkStreamID(ev.StreamID); err != nil {
			return Item{}, err
		}
		return Item{Seq: ev.Seq, Encoding: ev.Encoding, Body: ev.Body}, nil
	case frame.StreamEventEnd:
		if err := h.checkStreamID(ev.StreamID); err != nil {
			return Item{}, err
		}
		return Item{IsEOF: true}, nil
	case frame.StreamEventErr:
		if err := h.checkStreamID(ev.StreamID); err != nil {
			return Item{}, err
		}
		return Item{}, &ErrPeerAborted{Code: ev.Code, Message: ev.Message}
	default: // frame.StreamEventReply
		return Item{}, ErrUnexpectedFrame
	}
}

// AwaitReply blocks for the provider's terminal STREAM_REPLY
// (ClientStream/Bidi modes only) — call after CloseSend. Returns the
// reply payload and the responding node's id. A STREAM_REPLY that isn't
// signed by the key its responded_by names is dropped, with a drop warning,
// and AwaitReply goes on waiting for the genuine one until timeout.
func (h *Handle) AwaitReply(timeout time.Duration) (cbor.Value, []byte, error) {
	deadline := time.Now().Add(timeout)
	value, err := h.fs.RecvFrame(deadline)
	for err == nil && h.droppedReply(value) {
		value, err = h.fs.RecvFrame(deadline)
	}
	if err != nil {
		return cbor.Value{}, nil, fmt.Errorf("stream: await_reply: %w", err)
	}
	return h.replyFrom(value)
}

// droppedReply reports whether AwaitReply drops value: a STREAM_REPLY that
// isn't signed by the key its responded_by names.
func (h *Handle) droppedReply(value cbor.Value) bool {
	return frameTypeOf(value) == "stream_reply" && !h.fs.StreamReplyVerifies(value)
}

// replyFrom is what AwaitReply returns for value, a frame it didn't drop.
func (h *Handle) replyFrom(value cbor.Value) (cbor.Value, []byte, error) {
	ev, err := frame.ParseStreamEvent(value)
	if err != nil {
		return cbor.Value{}, nil, fmt.Errorf("stream: await_reply: %w", err)
	}
	if ev.Kind != frame.StreamEventReply && ev.Kind != frame.StreamEventErr {
		return cbor.Value{}, nil, ErrUnexpectedFrame // Data or End
	}
	if err := h.checkStreamID(ev.StreamID); err != nil {
		return cbor.Value{}, nil, err
	}
	if ev.Kind == frame.StreamEventErr {
		return cbor.Value{}, nil, &ErrPeerAborted{Code: ev.Code, Message: ev.Message}
	}
	return ev.Payload, ev.RespondedBy, nil
}

func frameTypeOf(v cbor.Value) string {
	ft, _ := v.Get("frame_type")
	t, _ := ft.AsText()
	return t
}

func (h *Handle) checkStreamID(streamID []byte) error {
	if string(streamID) == string(h.StreamID) {
		return nil
	}
	return ErrStreamIDMismatch
}

// Abort is non-normal termination: explicitly tell the peer this stream
// is aborting, per §13.1 point 4 — the only signal the peer gets to
// distinguish a cancellation/failure from a dropped connection.
// Best-effort, like connection.Session.Close's GOODBYE.
func (h *Handle) Abort(code, message string, id identity.KeyPair) {
	spec := frame.NewStreamErrorSpec(h.StreamID, code, message, id.NodeID())
	signed := frame.Sign(frame.StreamErrorFrame(spec), id)
	_ = h.fs.SendFrame(signed) // best-effort -- the stream is aborting regardless
}

// Refuse is the provider turning down a stream Accept handed it, the way
// every macula stack refuses a verified STREAM_OPEN: it writes a
// STREAM_ERROR with code and message, finishes its side of the stream so the
// error reaches the caller, and stops receiving with
// connection.StreamRefusedCode. Use "not_found" with "procedure not
// advertised" for a procedure the provider doesn't serve, and "unauthorized"
// with "not authorized for this procedure" for a caller it won't serve. When
// the STREAM_ERROR can't be written, the stream is reset and stopped with the
// refusal code instead.
func (h *Handle) Refuse(code, message string, id identity.KeyPair) error {
	spec := frame.NewStreamErrorSpec(h.StreamID, code, message, id.NodeID())
	if err := h.fs.SendFrame(frame.Sign(frame.StreamErrorFrame(spec), id)); err != nil {
		h.fs.Abort(connection.StreamRefusedCode)
		return fmt.Errorf("stream: refuse: %w", err)
	}
	err := h.fs.CloseSend()
	h.fs.StopReceiving(connection.StreamRefusedCode)
	if err != nil {
		return fmt.Errorf("stream: refuse: %w", err)
	}
	return nil
}
