package connection

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// dedicatedCall makes one Call on fs, answers it with each of replies in
// turn, built from the CALL's id, and returns what the call got.
func dedicatedCall(t *testing.T, fs *FrameStream, fc *fakeControl, replies ...func(callID []byte) cbor.Value) (frame.CallResponse, error) {
	t.Helper()
	caller := registryIdentity(t)
	type outcome struct {
		resp frame.CallResponse
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := fs.Call("_content.get_block", testRealm(), cbor.Null(), time.Now().Add(3*time.Second).UnixMilli(), caller, 3*time.Second)
		done <- outcome{resp, err}
	}()
	info, err := frame.ParseCall(fc.awaitSentOfType(t, "call", 1)[0])
	if err != nil {
		t.Fatalf("ParseCall: %v", err)
	}
	for _, reply := range replies {
		fc.send(t, reply(info.CallID))
	}
	select {
	case got := <-done:
		return got.resp, got.err
	case <-time.After(5 * time.Second):
		t.Fatal("the call never returned")
		return frame.CallResponse{}, nil
	}
}

// A RESULT or ERROR for the call on a dedicated stream counts only when it
// verifies against its responded_by or reported_by: a forged or unsigned one
// is dropped and the call keeps waiting for the genuine reply.
func TestADedicatedStreamReplyThatDoesNotVerifyLeavesTheCallWaiting(t *testing.T) {
	responder, other := fakeResponder(t), registryIdentity(t)
	result := func(callID []byte, tag string) cbor.Value {
		return frame.Result(frame.NewResultSpec(callID, cbor.Text(tag), responder.NodeID()))
	}
	notVerifying := map[string]func(callID []byte) cbor.Value{
		"a forged":    func(callID []byte) cbor.Value { return frame.Sign(result(callID, "forged"), other) },
		"an unsigned": func(callID []byte) cbor.Value { return result(callID, "unsigned") },
		"a forged error": func(callID []byte) cbor.Value {
			return frame.Sign(frame.CallErrorFrame(frame.NewCallErrorSpec(callID, bolt4.UnknownNextPeer, responder.NodeID())), other)
		},
	}
	for name, first := range notVerifying {
		t.Run(name, func(t *testing.T) {
			fc := newFakeControl()
			t.Cleanup(func() { _ = fc.Close() })
			resp, err := dedicatedCall(t, &FrameStream{stream: fc}, fc, first, genuineResultFrom(t))
			assertGenuine(t, name, resp, err)
		})
	}
}

// A reply dropped on a dedicated stream is warned about on the session the
// stream belongs to, as a dropped reply with its call_id prefix.
func TestADedicatedStreamReplyDroppedIsWarnedAboutOnItsSession(t *testing.T) {
	s, _, _ := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	intervals := captureDropIntervals(s)
	responder, other := fakeResponder(t), registryIdentity(t)
	fc := newFakeControl()
	t.Cleanup(func() { _ = fc.Close() })
	otherCall := append([]byte{0xca, 0xfe, 0xba, 0xbe}, make([]byte, 12)...)
	var forgedPrefix string
	forged := func(callID []byte) cbor.Value {
		forgedPrefix = fmt.Sprintf("%X", callID[:4])
		return frame.Sign(frame.Result(frame.NewResultSpec(callID, cbor.Text("forged"), responder.NodeID())), other)
	}
	forAnotherCall := func([]byte) cbor.Value {
		return frame.Sign(frame.Result(frame.NewResultSpec(otherCall, cbor.Text("late"), responder.NodeID())), responder)
	}

	resp, err := dedicatedCall(t, &FrameStream{stream: fc, session: s}, fc, forged, forAnotherCall, genuineResultFrom(t))
	assertGenuine(t, "a forged and a misaddressed", resp, err)
	intervals.endAll()

	lines := dropWarnings(logged)
	if len(lines) != 2 ||
		!hasFields(lines[0], "kind=dropped_reply", "count=1", "reason=invalid_signature", "call_id="+forgedPrefix) ||
		!hasFields(lines[1], "kind=dropped_reply", "count=1", "reason=unknown_call_id", "call_id=CAFEBABE") {
		t.Fatalf("drop warnings = %q, want the forged reply at once and the misaddressed one in the closing line", lines)
	}
}

// A STREAM_REPLY that isn't signed by the key its responded_by names doesn't
// verify, and is warned about on the stream's session as a dropped reply with
// its stream_id prefix; a genuine one verifies without a warning.
func TestAStreamReplyThatDoesNotVerifyIsWarnedAboutAsADroppedReply(t *testing.T) {
	s, _, _ := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	intervals := captureDropIntervals(s)
	responder, other := fakeResponder(t), registryIdentity(t)
	fs := &FrameStream{stream: &fakeQUICStream{}, session: s}
	streamID := append([]byte{0xab, 0xcd, 0xef, 0x01}, make([]byte, 12)...)
	reply := frame.StreamReply(frame.NewStreamReplySpec(streamID, cbor.Text("done"), responder.NodeID()))

	if !fs.StreamReplyCounts(frame.Sign(reply, responder), streamID) {
		t.Fatal("a STREAM_REPLY signed by its responder didn't verify")
	}
	if fs.StreamReplyCounts(reply, streamID) || fs.StreamReplyCounts(frame.Sign(reply, other), streamID) {
		t.Fatal("a STREAM_REPLY that isn't signed by its responder verified")
	}
	intervals.endAll()

	lines := dropWarnings(logged)
	if len(lines) != 2 ||
		!hasFields(lines[0], "kind=dropped_reply", "count=1", "reason=unsigned", "stream_id=ABCDEF01") ||
		!hasFields(lines[1], "kind=dropped_reply", "count=1", "reason=invalid_signature", "stream_id=ABCDEF01") {
		t.Fatalf("drop warnings = %q, want the unsigned reply at once and the forged one in the closing line", lines)
	}
}

// A STREAM_REPLY signed by its responder still isn't the reply when it doesn't
// parse or is for another stream: it is warned about as a dropped reply,
// malformed, or unknown_call_id with the other stream's id prefix.
func TestASignedStreamReplyThatDoesNotParseOrIsForAnotherStreamIsDropped(t *testing.T) {
	s, _, _ := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	intervals := captureDropIntervals(s)
	responder := fakeResponder(t)
	fs := &FrameStream{stream: &fakeQUICStream{}, session: s}
	streamID := append([]byte{0xab, 0xcd, 0xef, 0x01}, make([]byte, 12)...)
	otherStream := append([]byte{0xca, 0xfe, 0xba, 0xbe}, make([]byte, 12)...)
	reply := func(id []byte) cbor.Value {
		return frame.StreamReply(frame.NewStreamReplySpec(id, cbor.Text("done"), responder.NodeID()))
	}
	unparsed := frame.Sign(withoutField(reply(streamID), "payload"), responder)
	forAnotherStream := frame.Sign(reply(otherStream), responder)

	if fs.StreamReplyCounts(unparsed, streamID) || fs.StreamReplyCounts(forAnotherStream, streamID) {
		t.Fatal("a signed STREAM_REPLY that doesn't parse or is for another stream counted")
	}
	if !fs.StreamReplyCounts(frame.Sign(reply(streamID), responder), streamID) {
		t.Fatal("a signed STREAM_REPLY for the stream didn't count")
	}
	intervals.endAll()

	lines := dropWarnings(logged)
	if len(lines) != 2 ||
		!hasFields(lines[0], "kind=dropped_reply", "count=1", "reason=malformed", "stream_id=ABCDEF01") ||
		!hasFields(lines[1], "kind=dropped_reply", "count=1", "reason=unknown_call_id", "stream_id=CAFEBABE") {
		t.Fatalf("drop warnings = %q, want the unparsed reply at once and the other stream's in the closing line", lines)
	}
}
