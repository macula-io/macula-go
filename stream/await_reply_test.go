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
// counts a STREAM_REPLY that verifies against its responded_by and carries the
// stream id AwaitReply asks about.
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

func (r *replyingStream) StreamReplyCounts(v cbor.Value, streamID []byte) bool {
	signer, _ := v.Get("responded_by")
	key, _ := signer.AsBytes()
	id, _ := v.Get("stream_id")
	raw, _ := id.AsBytes()
	return frame.Verify(v, key) == nil && bytes.Equal(raw, streamID)
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

// AwaitReply asks about each STREAM_REPLY for its own stream, so a signed
// reply for another stream is dropped and it goes on waiting for its own.
func TestAStreamReplyForAnotherStreamLeavesTheReplyPending(t *testing.T) {
	provider, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	streamID, otherStream := make([]byte, 16), bytes.Repeat([]byte{0xca}, 16)
	reply := func(id []byte, tag string) cbor.Value {
		return frame.Sign(frame.StreamReply(frame.NewStreamReplySpec(id, cbor.Text(tag), provider.NodeID())), provider)
	}
	stream := &replyingStream{frames: []cbor.Value{reply(otherStream, "another stream's"), reply(streamID, "genuine")}}
	h := &Handle{fs: stream, StreamID: streamID, Mode: frame.ClientStream}
	payload, _, err := h.AwaitReply(time.Second)
	tag, _ := payload.AsText()
	if err != nil || tag != "genuine" {
		t.Fatalf("a reply for another stream first: AwaitReply = %q (err %v), want the genuine reply", tag, err)
	}
}
