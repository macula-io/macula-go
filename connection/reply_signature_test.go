package connection

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// replySequence makes one call on a reading session, sends each of replies,
// built from the CALL's id, in turn, and returns what the call got.
func replySequence(t *testing.T, replies ...func(callID []byte) cbor.Value) (frame.CallResponse, error) {
	t.Helper()
	s, fc, id := readingSession(t)
	type outcome struct {
		resp frame.CallResponse
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := s.Call("anything", testRealm(), cbor.Null(), time.Now().Add(3*time.Second).UnixMilli(), id, 3*time.Second)
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

// genuineResultFrom is a RESULT tagged "genuine" signed by responder.
func genuineResultFrom(t *testing.T) func(callID []byte) cbor.Value {
	responder := fakeResponder(t)
	return func(callID []byte) cbor.Value {
		return frame.Sign(frame.Result(frame.NewResultSpec(callID, cbor.Text("genuine"), responder.NodeID())), responder)
	}
}

func assertGenuine(t *testing.T, first string, resp frame.CallResponse, err error) {
	t.Helper()
	if err != nil || resp.IsError {
		t.Fatalf("%s reply first: the call got %+v, %v; want the genuine result", first, resp, err)
	}
	if tag, _ := resp.Payload.AsText(); tag != "genuine" {
		t.Fatalf("%s reply first: the call got the result tagged %q, want the genuine one", first, tag)
	}
}

// A RESULT that doesn't verify against its responded_by, forged or unsigned,
// is dropped and leaves the call waiting, so the genuine RESULT after it is
// the one the call gets.
func TestAResultThatDoesNotVerifyLeavesTheCallPending(t *testing.T) {
	responder, other := fakeResponder(t), registryIdentity(t)
	result := func(callID []byte, tag string) cbor.Value {
		return frame.Result(frame.NewResultSpec(callID, cbor.Text(tag), responder.NodeID()))
	}
	forged := func(callID []byte) cbor.Value { return frame.Sign(result(callID, "forged"), other) }
	unsigned := func(callID []byte) cbor.Value { return result(callID, "unsigned") }

	resp, err := replySequence(t, forged, genuineResultFrom(t))
	assertGenuine(t, "a forged", resp, err)
	resp, err = replySequence(t, unsigned, genuineResultFrom(t))
	assertGenuine(t, "an unsigned", resp, err)
}

// An ERROR that doesn't verify against its reported_by, forged or unsigned,
// is dropped and leaves the call waiting for the genuine reply.
func TestAnErrorThatDoesNotVerifyLeavesTheCallPending(t *testing.T) {
	responder, other := fakeResponder(t), registryIdentity(t)
	refusal := func(callID []byte) cbor.Value {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callID, bolt4.UnknownNextPeer, responder.NodeID()))
	}
	forged := func(callID []byte) cbor.Value { return frame.Sign(refusal(callID), other) }

	resp, err := replySequence(t, forged, genuineResultFrom(t))
	assertGenuine(t, "a forged", resp, err)
	resp, err = replySequence(t, refusal, genuineResultFrom(t))
	assertGenuine(t, "an unsigned", resp, err)
}
