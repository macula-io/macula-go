package stationlink

import (
	"context"
	"crypto/mldsa"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

// dropped is a station closing the caller's connection with QUIC application
// code 0, which is what this SDK measured a caller holding before this package:
// the transport's own error, with nothing in stationlink's vocabulary to
// classify it (macula-go#75, macula-sponsors#484).
func dropped(t *testing.T, s *testStation) *quic.ApplicationError {
	t.Helper()
	s.dropConn()
	return &quic.ApplicationError{Remote: true, ErrorCode: 0, ErrorMessage: "dropped"}
}

// endedCall runs a call in the background, waits until the station has the
// CALL, then ends the link, and returns the call's error: the path a station
// dropping a caller's link mid-request takes.
func endedCall(t *testing.T, link *Link, s *testStation, ends <-chan struct{}) error {
	t.Helper()
	out := make(chan error, 1)
	go func() {
		_, err := link.Call(context.Background(), stationCall(ProcedureFindRecord, cbor.Text("held")))
		out <- err
	}()
	select {
	case <-ends:
	case <-time.After(10 * time.Second):
		t.Fatal("the CALL never reached the station")
	}
	s.dropConn()
	select {
	case err := <-out:
		return err
	case <-time.After(20 * time.Second):
		t.Fatal("the call never returned after its link ended")
		return nil
	}
}

// namedEnding asserts err is the link's ending, named want, and returns it: the
// value a caller holds, the question errors.Is answers, and the name in the
// message cannot disagree (macula-go#75).
func namedEnding(t *testing.T, err error, want string) *LinkEndedError {
	t.Helper()
	var ended *LinkEndedError
	if !errors.As(err, &ended) {
		t.Fatalf("%v (%T), want a *LinkEndedError", err, err)
	}
	if !errors.Is(err, ErrLinkEnded) {
		t.Errorf("errors.Is(err, ErrLinkEnded) is false for %v", err)
	}
	if got := EndReason(err); got != want {
		t.Errorf("EndReason: %q, want %q", got, want)
	}
	if !strings.Contains(err.Error(), "("+want+")") {
		t.Errorf("the message does not name the ending: %v", err)
	}
	return ended
}

// A call whose link the station ends is named as the link's ending: the caller
// can tell a station that never answered because its link died from a provider
// that answered an error, and the transport's own close is still reachable
// with errors.As (macula-go#75).
func TestACallWhoseLinkEndsNamesTheEnding(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s := linkWithStation(t, p)
			reached := make(chan struct{}, 1)
			s.answerCalls(func(frame.VerifiedRequest) (cbor.Value, bool) {
				select {
				case reached <- struct{}{}:
				default:
				}
				return cbor.Value{}, false
			})
			err := endedCall(t, link, s, reached)
			namedEnding(t, err, "closed_by_station")

			var app *quic.ApplicationError
			if !errors.As(err, &app) || !app.Remote {
				t.Errorf("the transport's close is not reachable from %v", err)
			}
			if !link.NotCarried(err) {
				t.Error("the link says it carried a call its own ending returned")
			}
		})
	}
}

// Every ending a link can have is named, with the same name EndReason gives it:
// the message, EndReason of the value a caller holds and EndReason of the
// ending itself cannot disagree (macula-go#75).
func TestEveryEndingIsNamedTheSame(t *testing.T) {
	endings := map[string]error{
		"liveness_lost":     ErrLivenessLost,
		"closed":            ErrClosed,
		"goodbye":           &GoodbyeError{Reason: "station_draining"},
		"status_expired":    ErrStatusExpired,
		"binding_expired":   ErrBindingExpired,
		"malformed_frame":   frame.ErrMalformedFrame,
		"idle_timeout":      &quic.IdleTimeoutError{},
		"closed_by_station": &quic.ApplicationError{Remote: true, ErrorCode: 0, ErrorMessage: "dropped"},
		"connection_lost":   errors.New("read: connection reset"),
	}
	for name, ending := range endings {
		t.Run(name, func(t *testing.T) {
			link, _ := linkWithStation(t, profile.PQPure)
			out := make(chan error, 1)
			go func() {
				_, err := link.Call(context.Background(), stationCall(ProcedureFindRecord, cbor.Text("held")))
				out <- err
			}()
			link.end(ending)
			var err error
			select {
			case err = <-out:
			case <-time.After(20 * time.Second):
				t.Fatal("the call never returned after its link ended")
			}
			want := EndReason(ending)
			if want != name {
				t.Fatalf("EndReason(%v) is %q, want %q: the table names the ending wrongly", ending, want, name)
			}
			namedEnding(t, err, want)
		})
	}
}

// A CALL the link could not write in the window before it records its own
// ending is still a call the link did not carry: the pool's walk depends on
// that arm alone while link.Err is nil, and the value is named as the ending
// the connection already knows (macula-go#75).
func TestAWriteBeforeTheEndingIsRecordedIsNamedAndNotCarried(t *testing.T) {
	remote := &quic.ApplicationError{Remote: true, ErrorCode: 0, ErrorMessage: "dropped"}
	restore := connEnded
	connEnded = func(*Link) error { return remote }
	t.Cleanup(func() { connEnded = restore })

	link := &Link{} // dialed by hand: no ending recorded, and no connection to ask
	writeErr := errors.New("write: stream reset")
	err := link.notSent(writeErr)
	if !errors.Is(err, ErrLinkEnded) {
		t.Fatalf("a write that failed as the connection closed: %v, want the link's ending", err)
	}
	var notSent *callNotSent
	if !errors.As(err, &notSent) {
		t.Error("the write failure is not in the not-carried chain: the pool's walk would stop here")
	}
	if !link.NotCarried(err) {
		t.Error("NotCarried is false while link.Err is nil: the call the link could not write was called carried")
	}
	if got := EndReason(err); got != "closed_by_station" {
		t.Errorf("EndReason: %q, want closed_by_station", got)
	}

	// A write failure neither the link nor its connection knows an ending for
	// stays the value it is today: this package does not invent an ending.
	connEnded = func(*Link) error { return nil }
	plain := link.notSent(writeErr)
	if errors.Is(plain, ErrLinkEnded) {
		t.Errorf("a write failure the link does not know ended it was named as an ending: %v", plain)
	}
	if !link.NotCarried(plain) {
		t.Error("a CALL the link could not write is not carried, whatever ended it or did not")
	}
}

// The window test above swaps connEnded for a value; the real one reads the
// connection's own cause, and this test calls it against a connection the
// station has dropped, so the read the not-sent path depends on runs under a
// test (macula-go#75).
func TestTheConnectionsOwnEndingIsReadFromTheConnection(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	s.dropConn()
	select {
	case <-link.conn.Context().Done():
	case <-time.After(10 * time.Second):
		t.Fatal("the connection never ended after the station dropped it")
	}
	ended := connEnded(link)
	if ended == nil {
		t.Fatal("the connection has ended and connEnded says the link has not")
	}
	if got := EndReason(ended); got != "closed_by_station" {
		t.Errorf("EndReason: %q, want closed_by_station", got)
	}
	var app *quic.ApplicationError
	if !errors.As(ended, &app) || !app.Remote {
		t.Errorf("the transport's close is not reachable from %v", ended)
	}
}

// A publication the link could not send because its link ended is named too:
// Publish and PublishSigned surface the same value as a call (macula-go#75).
func TestAPublishOnAnEndedLinkNamesTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	link.end(ErrClosed)
	err := link.Publish(Publication{Topic: "link-ended/topic", Payload: cbor.Text("event")})
	if !errors.Is(err, ErrLinkEnded) {
		t.Fatalf("Publish: %v, want the link's ending", err)
	}
	if got := EndReason(err); got != "closed" {
		t.Errorf("EndReason: %q, want closed", got)
	}
}

// An open on a link that has ended carries the ending that ended it, not
// ErrClosed: ErrClosed is what a link its own owner closed ends with, and a
// station that dropped the link ends it with the transport's close
// (macula-go#75).
func TestAnOpenOnAnEndedLinkNamesWhatEndedIt(t *testing.T) {
	for name, ending := range map[string]error{
		"closed_by_station": &quic.ApplicationError{Remote: true, ErrorCode: 0, ErrorMessage: "dropped"},
		"closed":            ErrClosed,
		"goodbye":           &GoodbyeError{Reason: "station_draining"},
	} {
		t.Run(name, func(t *testing.T) {
			link, _ := linkWithStation(t, profile.PQPure)
			link.end(ending)
			_, err := link.OpenStream(context.Background(), StreamCall{Procedure: "mcl-tube/watch"})
			if !errors.Is(err, ErrLinkEnded) {
				t.Fatalf("OpenStream: %v, want the link's ending", err)
			}
			if got := EndReason(err); got != EndReason(ending) {
				t.Errorf("EndReason: %q, want %q", got, EndReason(ending))
			}
			if name == "closed_by_station" && errors.Is(err, ErrClosed) {
				t.Error("a station's close was named as the link's owner closing it")
			}
		})
	}
}

// A SUBSCRIBE waiting for its station when the link ends is named as the
// ending, like a call: the registration paths hand a caller the same value
// (macula-go#75).
func TestASubscribeWhoseLinkEndsNamesTheEnding(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	s.judge(func(kind string) (string, bool) { return "", kind == "subscribe" })
	out := make(chan error, 1)
	go func() {
		_, err := link.Subscribe([32]byte{1}, "link-ended/topic")
		out <- err
	}()
	s.next() // the SUBSCRIBE reached the station, which answers none
	s.dropConn()
	select {
	case err := <-out:
		if !errors.Is(err, ErrLinkEnded) {
			t.Fatalf("Subscribe: %v, want the link's ending", err)
		}
		if got := EndReason(err); got != "closed_by_station" {
			t.Errorf("EndReason: %q, want closed_by_station", got)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Subscribe never returned after its link ended")
	}
}

// A SUBSCRIBE written on a link that has already ended is named at the write
// itself, not only while its verdict is awaited: the frame never left the
// link, and the caller is told the link ended rather than handed the
// transport's raw close (macula-go#75).
func TestASubscribeOnAnEndedLinkNamesTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	link.end(ErrClosed)
	_, err := link.Subscribe([32]byte{1}, "link-ended/topic")
	namedEnding(t, err, "closed")
	link.mu.Lock()
	left := len(link.subs)
	link.mu.Unlock()
	if left != 0 {
		t.Errorf("%d subscriptions left on a link whose SUBSCRIBE was never written", left)
	}
}

// An ADVERTISE written on a link that has already ended is named too: a serve
// on a link that is gone is the same failure as a call, and an own-namespace
// procedure needs nothing but the write to reach it (macula-go#75).
func TestAServeOnAnEndedLinkNamesTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	link.end(ErrLivenessLost)
	own := record.OwnProcedure(link.NodeID(), "ring")
	_, err := link.Serve(context.Background(), Offer{Realm: [32]byte{1}, Procedure: own, Handler: echo})
	namedEnding(t, err, "liveness_lost")
}

// The renewal's own write is named as well: a served procedure whose ADVERTISE
// cannot be sent because the link ended says so in its error, and the renewal
// leaves on link.done before it gets there, so the write is driven here
// (macula-go#75).
func TestARenewalsAdvertisementOnAnEndedLinkNamesTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	link.end(ErrStatusExpired)
	err := link.announce(context.Background(), []byte("advertisement"))
	namedEnding(t, err, "status_expired")
}

// What is not the link's ending keeps its own value: a caller's cancellation,
// a call, a publication or an open over the frame cap and a station's answer
// are not the link failing to carry a request, and naming them as one would
// tell a caller its link died when it did not (macula-go#75).
func TestWhatIsNotTheLinksEndingIsNotNamed(t *testing.T) {
	t.Run("cancelled", aCancellationIsNotTheEnding)
	t.Run("station_answer", anAnswerIsNotTheEnding)
	t.Run("frame_too_large", aCallOverTheCapIsNotTheEnding)
	t.Run("publish_too_large", aPublicationOverTheCapIsNotTheEnding)
	t.Run("stream_open_too_large", anOpenOverTheCapIsNotTheEnding)
}

// aCancellationIsNotTheEnding: the caller gave up, the link did not.
func aCancellationIsNotTheEnding(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	s.answerCalls(func(frame.VerifiedRequest) (cbor.Value, bool) { return cbor.Value{}, false })
	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan error, 1)
	go func() {
		_, err := link.Call(ctx, stationCall(ProcedureFindRecord, cbor.Text("held")))
		out <- err
	}()
	time.Sleep(200 * time.Millisecond)
	cancel()
	err := <-out
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled call: %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrLinkEnded) {
		t.Errorf("a caller's own cancellation was named as the link's ending: %v", err)
	}
}

// anAnswerIsNotTheEnding: the station answered, so the link carried the call.
func anAnswerIsNotTheEnding(t *testing.T) {
	link, s := linkWithStation(t, profile.PQPure)
	detail := "no such key"
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		reply, err := frame.SignProviderError(r, "not_found", &detail, nil, s.key)
		return reply, err == nil
	})
	_, err := callWithin(t, link, stationCall(ProcedureFindRecord, cbor.Map(nil)))
	var provider *ProviderError
	if !errors.As(err, &provider) {
		t.Fatalf("the station's answer: %v, want the provider's error", err)
	}
	if errors.Is(err, ErrLinkEnded) {
		t.Errorf("a station's own answer was named as the link's ending: %v", err)
	}
}

// aCallOverTheCapIsNotTheEnding: every link refuses it, an ending or not.
func aCallOverTheCapIsNotTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	// Half a signature of headroom keeps the payload under the payload cap
	// and pushes the CALL that wraps it, signature and all, over the frame
	// cap, as stationlink/call_test.go does.
	payload := MaxFrameBytes - mldsa.MLDSA87().SignatureSize()/2
	_, err := callWithin(t, link, stationCall(ProcedureFindRecord, cbor.Bytes(make([]byte, payload))))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a call over the cap: %v, want ErrFrameTooLarge", err)
	}
	if errors.Is(err, ErrLinkEnded) {
		t.Errorf("a call every link refuses was named as the link's ending: %v", err)
	}
}

// aPublicationOverTheCapIsNotTheEnding: the write on a live link refuses it.
func aPublicationOverTheCapIsNotTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	err := link.PublishSigned(SignedPublication{encoded: make([]byte, MaxFrameBytes+1)})
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("a publication over the cap: %v, want ErrFrameTooLarge", err)
	}
	if errors.Is(err, ErrLinkEnded) {
		t.Errorf("a publication every link refuses was named as the link's ending: %v", err)
	}
}

// anOpenOverTheCapIsNotTheEnding: the open is refused before any stream exists.
func anOpenOverTheCapIsNotTheEnding(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	open := StreamCall{Procedure: "mcl-tube/watch", Payload: cbor.Bytes(make([]byte, streamOpenBytes))}
	_, err := link.OpenStream(context.Background(), open)
	if !errors.Is(err, ErrStreamOpenTooLarge) {
		t.Fatalf("an open over the cap: %v, want ErrStreamOpenTooLarge", err)
	}
	if errors.Is(err, ErrLinkEnded) {
		t.Errorf("an open every link refuses was named as the link's ending: %v", err)
	}
}

// A call on a link that has ended carries one name, not a stack of them: the
// wrapper is applied where the ending is produced, and not again on the way out
// (macula-go#75).
func TestACallOnAnEndedLinkCarriesOneName(t *testing.T) {
	link, _ := linkWithStation(t, profile.PQPure)
	link.end(ErrLivenessLost)
	_, err := callWithin(t, link, stationCall(ProcedureFindRecord, cbor.Text("held")))
	names := 0
	for probe := err; probe != nil; probe = errors.Unwrap(probe) {
		if _, ok := probe.(*LinkEndedError); ok {
			names++
		}
	}
	if names != 1 {
		t.Fatalf("the value carries %d link endings, want 1: %v", names, err)
	}
}
