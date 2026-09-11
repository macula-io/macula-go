package connection

import (
	"crypto/rand"
	"fmt"
	"io"
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
}

// FrameStream sends and receives signed application frames on one QUIC
// stream. The control stream (inside Session) and every dedicated
// stream (content transfer, streaming RPC) opened via
// Session.OpenDedicatedStream / Session.AcceptDedicatedStream are each
// one of these — see plans/PLAN_WIRE_PROTOCOL.md §3, §12, §13.
type FrameStream struct {
	stream quicStream
	buf    []byte     // bytes read but not yet consumed by a decoded frame
	sendMu sync.Mutex // held for one frame's write; see SendFrame
}

func newFrameStream(stream *quic.Stream) *FrameStream {
	return &FrameStream{stream: stream}
}

// SendFrame encodes and writes v to the stream. Frames sent from several
// goroutines at once are written whole, one after another, without relying
// on the stream to serialize concurrent writes: quic-go documents concurrent
// Write on a stream as not permitted.
func (fs *FrameStream) SendFrame(v cbor.Value) error {
	encoded, err := frame.Encode(v)
	if err != nil {
		return fmt.Errorf("connection: encode frame: %w", err)
	}
	fs.sendMu.Lock()
	defer fs.sendMu.Unlock()
	if _, err := fs.stream.Write(encoded); err != nil {
		return fmt.Errorf("connection: write frame: %w", err)
	}
	return nil
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

// RecvFrame reads the next complete application frame off the stream,
// using (and updating) fs.buf. deadline bounds the read (Stream.Read
// doesn't take a context directly); a zero deadline means no bound.
func (fs *FrameStream) RecvFrame(deadline time.Time) (cbor.Value, error) {
	if err := fs.stream.SetReadDeadline(deadline); err != nil {
		return cbor.Value{}, fmt.Errorf("connection: set read deadline: %w", err)
	}
	chunk := make([]byte, readChunkSize)
	for {
		decoded, err := frame.Decode(fs.buf)
		if err != nil {
			return cbor.Value{}, fmt.Errorf("connection: decode: %w", err)
		}
		if decoded.Complete {
			fs.buf = fs.buf[decoded.Consumed:]
			return decoded.Frame, nil
		}

		n, err := fs.stream.Read(chunk)
		if n > 0 {
			fs.buf = append(fs.buf, chunk[:n]...)
		}
		// Per io.Reader's contract, a Read that delivers the stream's
		// final bytes is explicitly permitted to return them together
		// with io.EOF in the same call — quic-go does exactly this
		// when the peer's last STREAM frame carries both the final
		// data and the FIN bit. Those bytes must still be checked for
		// a complete frame (the loop's next iteration does that)
		// before the error is allowed to end it; discarding them here
		// turned an already-fully-delivered reply into a bogus EOF
		// error. Only give up once a read truly comes back empty.
		if n == 0 && err != nil {
			return cbor.Value{}, fmt.Errorf("connection: read stream: %w", err)
		}
	}
}

// Call sends a signed CALL for procedure on this stream and waits for
// the matching RESULT or ERROR, correlated by call_id.
//
// Known v1 limitation (matches the control stream's own): any frame
// that arrives before the match is discarded, not queued or dispatched
// elsewhere. Harmless on a dedicated stream (content transfer, streaming
// RPC), since nothing else ever arrives there to discard; on the
// control stream it means Call and Publish/Subscribe used concurrently
// can race.
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
		gotID, ok := frame.FrameCallID(value)
		if !ok || string(gotID) != string(callID) {
			continue // not ours -- see this method's doc on the v1 limitation
		}
		response, err := frame.ParseCallResponse(value)
		if err != nil {
			// Matching call_id but not a result/error shape: keep
			// waiting rather than erroring, since nothing else in the
			// protocol is expected to carry this call's id.
			continue
		}
		return response, nil
	}
}
