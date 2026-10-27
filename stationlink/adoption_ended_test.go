package stationlink

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
)

// A stream its owner ends while an adoption is in flight keeps that ending: the
// session the reopen opened is released, never installed behind a stream that
// is already gone, so a provider is never handed a copy on behalf of a stream
// its owner has closed.
//
// The interleaving this pins is the reachable one, and it is not the owner's
// Close racing the reader for the send mutex: Close sends its STREAM_END under
// that mutex and ends the stream after it, so its end lands between the
// adoption taking the mutex and the adoption installing what the reopen
// returned. Everything the install would have changed (the session, this side's
// send numbering and end) must be untouched when the adoption returns.
func TestAnAdoptionInstallsNothingBehindAnEndedStream(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) { assertAnAdoptionInstallsNothing(t, p) })
	}
}

func assertAnAdoptionInstallsNothing(t *testing.T, p profile.Profile) {
	t.Helper()
	link, _ := linkWithStation(t, p)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := link.OpenStream(ctx, StreamCall{Procedure: "mcl-vault/count", Mode: frame.Bidi,
		Payload: cbor.Map(nil), Clear: true})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if stream.reopen == nil || stream.retained == nil {
		t.Fatal("a clear stream keeps no call to reopen under and no copy to replay")
	}
	copied := frame.StreamDataFields{Encoding: frame.Raw, Body: cbor.Bytes([]byte("before the end"))}
	stream.retain(copied, false, 64)
	stream.mu.Lock()
	session, seq := stream.qs, stream.sendSeq
	stream.mu.Unlock()

	// The owner ends the stream, as Close does once its STREAM_END is sent,
	// while the adoption holds the send mutex between taking the copy and
	// installing the session the reopen opens.
	stream.end(nil)
	stream.sendMu.Lock()
	stream.adopt([]retainedAction{{fields: copied}}, carriedKeyOf(t, p))
	stream.sendMu.Unlock()

	stream.mu.Lock()
	installed, replaySeq, ended := stream.qs, stream.sendSeq, stream.sentEnd
	stream.mu.Unlock()
	if installed != session {
		t.Error("the adoption installed the session it opened behind a stream its owner had ended")
	}
	if replaySeq != seq || !ended {
		t.Errorf("the adoption adopted the session: seq %d and sentEnd %v, want %d and true", replaySeq, ended, seq)
	}
}
