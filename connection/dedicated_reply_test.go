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
