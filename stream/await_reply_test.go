package stream

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// replyingStream is a dedicated stream handing out frames in order, which
// checks a STREAM_REPLY's signature against its responded_by.
type replyingStream struct {
	refusingStream
	frames []cbor.Value
}

func (r *replyingStream) RecvFrame(time.Time) (cbor.Value, error) {
	if len(r.frames) == 0 {
		return cbor.Value{}, errors.New("replyingStream: no more frames")
	}
	next := r.frames[0]
	r.frames = r.frames[1:]
	return next, nil
}

func (r *replyingStream) StreamReplyVerifies(v cbor.Value) bool {
	signer, _ := v.Get("responded_by")
	key, _ := signer.AsBytes()
	return frame.Verify(v, key) == nil
}

// A STREAM_REPLY that doesn't verify against its responded_by, forged or
// unsigned, is dropped, and AwaitReply goes on waiting for the genuine one.
func TestAStreamReplyThatDoesNotVerifyLeavesTheReplyPending(t *testing.T) {
	provider, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	other, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	streamID := make([]byte, 16)
	reply := func(tag string) cbor.Value {
		return frame.StreamReply(frame.NewStreamReplySpec(streamID, cbor.Text(tag), provider.NodeID()))
	}
	firsts := map[string]cbor.Value{"forged": frame.Sign(reply("forged"), other), "unsigned": reply("unsigned")}
	for name, first := range firsts {
		stream := &replyingStream{frames: []cbor.Value{first, frame.Sign(reply("genuine"), provider)}}
		h := &Handle{fs: stream, StreamID: streamID, Mode: frame.ClientStream}
		payload, respondedBy, err := h.AwaitReply(time.Second)
		tag, _ := payload.AsText()
		if err != nil || tag != "genuine" || !bytes.Equal(respondedBy, provider.NodeID()) {
			t.Fatalf("a %s reply first: AwaitReply = %q (err %v), want the genuine reply", name, tag, err)
		}
	}
}
