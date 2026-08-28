package connection

import (
	"crypto/rand"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
)

// readChunkSize is how much is read per Stream.Read call while
// accumulating a frame.
const readChunkSize = 4096

// FrameStream sends and receives signed application frames on one QUIC
// stream. The control stream (inside Session) and every dedicated
// stream (content transfer, streaming RPC) opened via
// Session.OpenDedicatedStream / Session.AcceptDedicatedStream are each
// one of these — see plans/PLAN_WIRE_PROTOCOL.md §3, §12, §13.
type FrameStream struct {
	stream *quic.Stream
	buf    []byte // bytes read but not yet consumed by a decoded frame
}

func newFrameStream(stream *quic.Stream) *FrameStream {
	return &FrameStream{stream: stream}
}

// SendFrame encodes and writes v to the stream.
func (fs *FrameStream) SendFrame(v cbor.Value) error {
	encoded, err := frame.Encode(v)
	if err != nil {
		return fmt.Errorf("connection: encode frame: %w", err)
	}
	if _, err := fs.stream.Write(encoded); err != nil {
		return fmt.Errorf("connection: write frame: %w", err)
	}
	return nil
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
		if err != nil {
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
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		return frame.CallResponse{}, fmt.Errorf("connection: generate call_id: %w", err)
	}
	spec := frame.NewCallSpec(callID, procedure, realm, payload, deadlineMs, id.NodeID())
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
