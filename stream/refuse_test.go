package stream

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// refusingStream is a dedicated stream recording, in order, what a provider
// does with it.
type refusingStream struct {
	did  []string
	sent []cbor.Value
}

func (r *refusingStream) SendFrame(v cbor.Value) error {
	r.did = append(r.did, "write")
	r.sent = append(r.sent, v)
	return nil
}

func (r *refusingStream) RecvFrame(time.Time) (cbor.Value, error) {
	return cbor.Value{}, errors.New("refusingStream: nothing to read")
}

func (r *refusingStream) CloseSend() error {
	r.did = append(r.did, "finish")
	return nil
}

func (r *refusingStream) Abort(code uint64) { r.did = append(r.did, fmt.Sprintf("abort %d", code)) }

func (r *refusingStream) StreamReplyVerifies(cbor.Value) bool { return true }

func (r *refusingStream) StopReceiving(code uint64) {
	r.did = append(r.did, fmt.Sprintf("stop receiving %d", code))
}

// A provider refusing a stream it was handed writes the STREAM_ERROR saying
// why, signed by the provider, then finishes its side of the stream, then
// stops receiving with the refusal code.
func TestARefusedStreamWritesItsErrorThenFinishesAndStopsReading(t *testing.T) {
	provider, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	refused := &refusingStream{}
	h := &Handle{fs: refused, StreamID: make([]byte, 16), Mode: frame.ServerStream}

	if err := h.Refuse("unauthorized", "not authorized for this procedure", provider); err != nil {
		t.Fatalf("Refuse: %v", err)
	}
	if want := []string{"write", "finish", fmt.Sprintf("stop receiving %d", connection.StreamRefusedCode)}; !slices.Equal(refused.did, want) {
		t.Fatalf("refusing did %q, want %q", refused.did, want)
	}
	ev, err := frame.ParseStreamEvent(refused.sent[0])
	if err != nil || ev.Kind != frame.StreamEventErr || ev.Code != "unauthorized" || ev.Message != "not authorized for this procedure" {
		t.Fatalf("the frame written is %+v (err %v), want the STREAM_ERROR with the code and message given", ev, err)
	}
	if err := frame.Verify(refused.sent[0], provider.NodeID()); err != nil {
		t.Fatalf("the STREAM_ERROR doesn't verify against the provider: %v", err)
	}
}
