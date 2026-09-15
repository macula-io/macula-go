package connection

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// awaitOutcome is the next PublishOutcome a RunPublisher delivers on outcomes.
func awaitOutcome(t *testing.T, outcomes <-chan PublishOutcome) PublishOutcome {
	t.Helper()
	select {
	case outcome := <-outcomes:
		return outcome
	case <-time.After(2 * time.Second):
		t.Fatal("no publish outcome within 2s")
		return PublishOutcome{}
	}
}

// A RunPublisher for a publication a station refuses delivers the refusal as its
// outcome before anything is announced or sent: no PUBLISH, no facts, and no
// refused fact warned about. A RunPublisher beside it publishes with both its
// facts.
func TestARunPublisherForAPublicationAStationRefusesSendsNothing(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	captureDropIntervals(s)
	outcomes := make(chan PublishOutcome, 2)
	onDone := func(outcome PublishOutcome) { outcomes <- outcome }

	refused := frame.NewPublishSpec("a.topic", testRealm()[:31], id.NodeID(), 1, cbor.Null(), time.Now().UnixMilli())
	s.RunPublisher(refused, id, true, onDone)
	if outcome := awaitOutcome(t, outcomes); outcome.Cancelled || !errors.Is(outcome.Err, frame.ErrOutOfRange) {
		t.Errorf("the refused publish's outcome: %+v, want its refusal", outcome)
	}
	valid := frame.NewPublishSpec("a.topic", testRealm(), id.NodeID(), 2, cbor.Null(), time.Now().UnixMilli())
	s.RunPublisher(valid, id, true, onDone)
	if outcome := awaitOutcome(t, outcomes); outcome.Cancelled || outcome.Err != nil {
		t.Fatalf("the valid publish's outcome: %+v, want it completed", outcome)
	}
	fc.awaitSentOfType(t, "publish", 3)
	if n := len(fc.sentOfType(t, "publish")); n != 3 {
		t.Errorf("PUBLISH frames written: %d, want 3, the valid publish and its two facts alone", n)
	}
	if lines := dropWarnings(logged); len(lines) != 0 {
		t.Errorf("drop warnings = %q, want none, since the refused publish never started", lines)
	}
}

// One of this session's own facts whose PUBLISH the builder refuses, for a realm
// that is not 32 bytes, is never written and is warned about as a refused_fact
// drop naming its topic, so it does not disappear unseen. A fact beside it is
// written.
func TestARefusedFactIsWarnedAboutAsADrop(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	captureDropIntervals(s)

	announceRPCSent(s, testRealm()[:31], id, randomID())
	if lines := dropWarnings(logged); len(lines) != 1 ||
		!hasFields(lines[0], "kind=refused_fact", "count=1", "reason=out_of_range", "topic="+rpcSentTopic) {
		t.Errorf("drop warnings = %q, want one refused_fact line for %s", lines, rpcSentTopic)
	}
	announceRPCSent(s, testRealm(), id, randomID())
	fc.awaitSentOfType(t, "publish", 1)
	if n := len(fc.sentOfType(t, "publish")); n != 1 {
		t.Errorf("PUBLISH frames written: %d, want 1, the fact with a 32-byte realm alone", n)
	}
}

// Every topic this package publishes its facts under is one a station reads, so
// a fact is refused for its realm alone.
func TestTheFactTopicsAreTopicsAStationReads(t *testing.T) {
	for _, topic := range []string{publishStartedTopic, publishCompletedTopic, rpcSentTopic, rpcCompletedTopic, rpcReceivedTopic, rpcRepliedTopic} {
		if err := frame.CheckPublication(testRealm(), topic); err != nil {
			t.Errorf("the fact topic %q: %v, want a topic a station reads", topic, err)
		}
	}
}
