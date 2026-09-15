package connection

import (
	"bytes"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
)

// factsOn is every fact the session has written on topic, in the order it
// wrote them.
func factsOn(t *testing.T, fc *fakeControl, topic string) []cbor.Value {
	t.Helper()
	var out []cbor.Value
	for _, v := range fc.sentOfType(t, "publish") {
		field, _ := v.Get("topic")
		if written, _ := field.AsBytes(); bytes.Equal(written, []byte(topic)) {
			out = append(out, v)
		}
	}
	return out
}

// requestIDOf is an RPC fact's request_id.
func requestIDOf(fact cbor.Value) []byte {
	payload, _ := fact.Get("payload")
	field, _ := payload.Get("request_id")
	id, _ := field.AsBytes()
	return id
}

// awaitFactsOn waits until the session has written n facts on topic, and
// returns them.
func awaitFactsOn(t *testing.T, fc *fakeControl, topic string, n int) []cbor.Value {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if facts := factsOn(t, fc, topic); len(facts) >= n {
			return facts
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the session wrote fewer than %d %s facts", n, topic)
	return nil
}

// awaitRepliedFor waits until the session has written an rpc.replied_v1 fact
// for requestID, and returns every rpc.replied_v1 fact written by then. Facts
// are written in the order they are announced, so every fact announced before
// that one is among them.
func awaitRepliedFor(t *testing.T, fc *fakeControl, requestID []byte) []cbor.Value {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		replied := factsOn(t, fc, rpcRepliedTopic)
		for _, f := range replied {
			if bytes.Equal(requestIDOf(f), requestID) {
				return replied
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the session never announced the answered call as replied")
	return nil
}

// A call is announced as replied once its reply is written, so a call whose
// reply was refused before it was written, and answered with an ERROR in its
// place, is never announced as replied.
func TestACallWhoseReplyIsRefusedIsNotAnnouncedAsReplied(t *testing.T) {
	s, fc, id := readingSession(t)
	if _, err := servedReply(t, s, fc, id, overTheBudget()); err != nil {
		t.Fatalf("serving the call whose reply is refused: %v", err)
	}
	if _, err := servedReply(t, s, fc, id, cbor.Null()); err != nil {
		t.Fatalf("serving the call that is answered: %v", err)
	}

	received := awaitFactsOn(t, fc, rpcReceivedTopic, 2)
	refused, answered := requestIDOf(received[0]), requestIDOf(received[1])
	for _, fact := range awaitRepliedFor(t, fc, answered) {
		if bytes.Equal(requestIDOf(fact), refused) {
			t.Fatal("the call whose reply was refused was announced as replied")
		}
	}
}
