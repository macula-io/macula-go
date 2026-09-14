package stream

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// acceptedStream is one dedicated stream a provider accepts, whose first
// frame the test sets, recording what the provider does with it.
type acceptedStream struct {
	first   cbor.Value
	sent    []cbor.Value
	closed  bool
	aborted *uint64
}

func (a *acceptedStream) RecvFrame(time.Time) (cbor.Value, error) { return a.first, nil }
func (a *acceptedStream) SendFrame(v cbor.Value) error            { a.sent = append(a.sent, v); return nil }
func (a *acceptedStream) CloseSend() error                        { a.closed = true; return nil }
func (a *acceptedStream) Abort(code uint64)                       { a.aborted = &code }

func testIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func streamOpenFrom(caller identity.KeyPair, procedure string) cbor.Value {
	streamID := make([]byte, 16)
	streamID[0] = byte(len(procedure))
	spec := frame.NewStreamOpenSpec(streamID, procedure, make([]byte, 32), frame.ServerStream, cbor.Null(),
		time.Now().Add(time.Minute).UnixMilli(), caller.NodeID())
	return frame.StreamOpen(spec)
}

// A STREAM_OPEN not signed by the caller it names is refused, and so is a
// first frame of another type: neither reaches the provider, nothing is
// written on its stream, and the stream is aborted in both directions. A
// genuine STREAM_OPEN after them is served.
func TestAStreamOpenNotSignedByItsCallerIsRefused(t *testing.T) {
	caller, other := testIdentity(t), testIdentity(t)
	forged := &acceptedStream{first: frame.Sign(streamOpenFrom(caller, "forged"), other)}
	unsigned := &acceptedStream{first: streamOpenFrom(caller, "unsigned")}
	otherType := &acceptedStream{first: frame.Sign(frame.StreamEnd(frame.NewStreamEndSpec(make([]byte, 16), frame.Send, caller.NodeID())), caller)}
	genuine := &acceptedStream{first: frame.Sign(streamOpenFrom(caller, "genuine"), caller)}
	pending := []*acceptedStream{forged, unsigned, otherType, genuine}
	accept := func(context.Context) (frameStream, error) {
		next := pending[0]
		pending = pending[1:]
		return next, nil
	}

	handle, open, err := acceptStreamOpen(context.Background(), time.Second, accept)
	if err != nil {
		t.Fatalf("acceptStreamOpen: %v", err)
	}
	if open.Procedure != "genuine" || handle.fs != frameStream(genuine) {
		t.Fatalf("served the STREAM_OPEN for %q, want only the genuine one", open.Procedure)
	}
	for name, refused := range map[string]*acceptedStream{"forged": forged, "unsigned": unsigned, "other type": otherType} {
		if len(refused.sent) != 0 {
			t.Fatalf("%s stream: %d frames written, want none", name, len(refused.sent))
		}
		if refused.aborted == nil {
			t.Fatalf("%s stream was not aborted", name)
		}
	}
	if genuine.aborted != nil || genuine.closed {
		t.Fatal("the genuine stream was ended, want it handed to the provider open")
	}
}
