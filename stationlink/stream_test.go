package stationlink_test

import (
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

const streamProcedure = "mcl-tube/watch"

// streamWorld is one station, a realm that admitted the org, a provider link
// and a caller link.
type streamWorld struct {
	station  *teststation.Station
	realm    teststation.Realm
	provider *stationlink.Link
	caller   *stationlink.Link
}

func dialAs(t *testing.T, s *teststation.Station, name string) *stationlink.Link {
	t.Helper()
	key := teststation.Key(t, profile.PQPure, name)
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := stationlink.Dial(ctx, stationlink.Config{Target: s.Target(), IdentityKey: key, Issuer: issuer})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = link.Close("test_done") })
	s.WaitAccepted()
	return link
}

func newStreamWorld(t *testing.T, name string) streamWorld {
	t.Helper()
	s := teststation.Start(t, profile.PQPure, name)
	realm := teststation.NewRealm(t, profile.PQPure, name, "mcl-tube")
	provider := dialAs(t, s, name+" provider")
	realm.Admit(t, s, provider.NodeID())
	return streamWorld{station: s, realm: realm, provider: provider, caller: dialAs(t, s, name+" caller")}
}

func (w streamWorld) serve(t *testing.T, mode frame.StreamMode, handler stationlink.StreamHandler) *stationlink.Served {
	t.Helper()
	served, err := w.provider.Serve(t.Context(), stationlink.Offer{Realm: w.realm.ID, Procedure: streamProcedure,
		Stream: &stationlink.StreamOffer{Mode: mode, Handler: handler}, RealmKey: w.realm.RealmKey()})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return served
}

func (w streamWorld) open(t *testing.T, mode frame.StreamMode, payload cbor.Value) *stationlink.Stream {
	t.Helper()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: streamProcedure,
		Target: w.provider.NodeID(), Mode: mode, Payload: payload})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	return stream
}

// released asserts every stream the station relayed has been released by both
// ends.
func (w streamWorld) released(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if w.station.Relayed() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("%d relayed streams were never released", w.station.Relayed())
}

func recv(t *testing.T, s *stationlink.Stream) (stationlink.StreamEvent, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	return s.Recv(ctx)
}

// A server stream delivers each chunk the provider sends, in order, then its
// end; the stream is released at both ends.
func TestAServerStreamDeliversEveryChunkThenEnds(t *testing.T) {
	w := newStreamWorld(t, "server stream")
	w.serve(t, frame.ServerStream, func(_ context.Context, s *stationlink.Stream) error {
		for _, chunk := range []string{"one", "two", "three"} {
			if err := s.Send([]byte(chunk)); err != nil {
				return err
			}
		}
		return s.Close()
	})
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	for _, want := range []string{"one", "two", "three"} {
		event, err := recv(t, stream)
		body, _ := event.Body.AsBytes()
		if err != nil || event.Kind != stationlink.StreamData || string(body) != want {
			t.Fatalf("chunk %q: %+v, %v", want, event, err)
		}
	}
	if event, err := recv(t, stream); err != nil || event.Kind != stationlink.StreamEnd {
		t.Errorf("the end: %+v, %v", event, err)
	}
	if _, err := recv(t, stream); !errors.Is(err, io.EOF) {
		t.Errorf("after the end: %v, want io.EOF", err)
	}
	w.released(t)
}

// A client stream's chunks reach the provider, whose REPLY answers them.
func TestAClientStreamIsAnsweredWithAReply(t *testing.T) {
	w := newStreamWorld(t, "client stream")
	w.serve(t, frame.ClientStream, func(ctx context.Context, s *stationlink.Stream) error {
		total := 0
		for {
			event, err := s.Recv(ctx)
			if err != nil {
				return err
			}
			if event.Kind == stationlink.StreamEnd {
				return s.Reply(cbor.Uint64(uint64(total)))
			}
			body, _ := event.Body.AsBytes()
			total += len(body)
		}
	})
	stream := w.open(t, frame.ClientStream, cbor.Map(nil))
	for _, chunk := range []string{"ab", "cde", "f"} {
		if err := stream.Send([]byte(chunk)); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	event, err := recv(t, stream)
	total, _ := event.Payload.AsInt64()
	if err != nil || event.Kind != stationlink.StreamReply || total != 6 {
		t.Errorf("the reply: %+v, %v", event, err)
	}
	w.released(t)
}

// A handler's error aborts the stream with code error and its text, and a
// panicking handler aborts it too; neither leaves a stream behind.
func TestAFailingHandlerAbortsTheStream(t *testing.T) {
	w := newStreamWorld(t, "failing")
	failing := func(context.Context, *stationlink.Stream) error { return errors.New("refused by the handler") }
	w.serve(t, frame.ServerStream, failing)
	var aborted *stationlink.StreamError
	if _, err := recv(t, w.open(t, frame.ServerStream, cbor.Map(nil))); !errors.As(err, &aborted) ||
		aborted.Code != "error" || aborted.Message != "refused by the handler" || aborted.Relay {
		t.Errorf("a handler's error: %v", err)
	}
	w.released(t)
	panicking := newStreamWorld(t, "panicking")
	panicking.serve(t, frame.ServerStream, func(context.Context, *stationlink.Stream) error { panic("boom") })
	if _, err := recv(t, panicking.open(t, frame.ServerStream, cbor.Map(nil))); !errors.As(err, &aborted) || aborted.Code != "error" {
		t.Errorf("a panicking handler: %v", err)
	}
	panicking.released(t)
}

// An open the provider refuses is refused with its code at seq 0 and released:
// a mode other than the one served, and a procedure the station does not route.
func TestARefusedOpenIsReleased(t *testing.T) {
	w := newStreamWorld(t, "refused")
	w.serve(t, frame.ServerStream, func(context.Context, *stationlink.Stream) error { return nil })
	var refused *stationlink.StreamError
	if _, err := recv(t, w.open(t, frame.Bidi, cbor.Map(nil))); !errors.As(err, &refused) || refused.Code != "mode_mismatch" {
		t.Errorf("another mode: %v", err)
	}
	unrouted, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-tube/nothing",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := recv(t, unrouted); !errors.As(err, &refused) || refused.Code != "unknown_next_peer" || !refused.Relay {
		t.Errorf("an unrouted procedure: %v", err)
	}
	w.released(t)
}

// A caller that abandons a stream, by Abort or by its link ending, releases
// it, and the provider's handler sees its context end.
func TestAnAbandonedStreamIsReleasedAtBothEnds(t *testing.T) {
	w := newStreamWorld(t, "abandoned")
	handlerDone := make(chan error, 2)
	w.serve(t, frame.Bidi, func(ctx context.Context, s *stationlink.Stream) error {
		_, err := s.Recv(ctx)
		handlerDone <- err
		return err
	})
	stream := w.open(t, frame.Bidi, cbor.Map(nil))
	if err := stream.Abort("cancelled", "the caller gave up"); err != nil {
		t.Fatalf("Abort: %v", err)
	}
	select {
	case err := <-handlerDone:
		var aborted *stationlink.StreamError
		if !errors.As(err, &aborted) || aborted.Code != "cancelled" {
			t.Errorf("the handler saw %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the handler never saw the abort")
	}
	w.released(t)
	w.open(t, frame.Bidi, cbor.Map(nil))
	_ = w.caller.Close("caller_gone")
	w.released(t)
}

// A session over the per-caller bound is refused too_many_sessions.
func TestSessionsAreBoundedPerCaller(t *testing.T) {
	restore := stationlink.SetStreamSessionLimits(1, 1000)
	t.Cleanup(restore)
	w := newStreamWorld(t, "sessions")
	hold := make(chan struct{})
	t.Cleanup(func() { close(hold) })
	w.serve(t, frame.ServerStream, func(ctx context.Context, s *stationlink.Stream) error {
		select {
		case <-hold:
		case <-ctx.Done():
		}
		return s.Close()
	})
	first := w.open(t, frame.ServerStream, cbor.Map(nil))
	var refused *stationlink.StreamError
	if _, err := recv(t, w.open(t, frame.ServerStream, cbor.Map(nil))); !errors.As(err, &refused) || refused.Code != "too_many_sessions" {
		t.Errorf("a second session: %v", err)
	}
	_ = first.Abort("done", "")
	w.released(t)
}

// A stream whose reader falls behind by more than its inbox bound is aborted
// resource_exhausted and released, rather than holding what arrives.
func TestAStreamOverItsInboxBoundIsAborted(t *testing.T) {
	restore := stationlink.SetStreamInboxBytes(64 * 1024)
	t.Cleanup(restore)
	w := newStreamWorld(t, "inbox")
	w.serve(t, frame.ServerStream, func(ctx context.Context, s *stationlink.Stream) error {
		chunk := make([]byte, 16*1024)
		for range 64 {
			if err := s.Send(chunk); err != nil {
				return nil
			}
		}
		return s.Close()
	})
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	select {
	case <-stream.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was never aborted")
	}
	var aborted *stationlink.StreamError
	if err := stream.Err(); !errors.As(err, &aborted) || aborted.Code != "resource_exhausted" {
		t.Errorf("the stream ended with %v", err)
	}
	w.released(t)
}

// A dedicated stream the station opens that does not begin with a STREAM_OPEN,
// or does not deliver its first frame within the open's wait, is released by
// the link before any session exists. (A stream nothing is written on is never
// seen by the peer at all, so the stall is a frame begun and not finished.)
func TestAStreamThatDoesNotOpenIsReleased(t *testing.T) {
	restore := stationlink.SetStreamOpenWait(200 * time.Millisecond)
	t.Cleanup(restore)
	s := teststation.Start(t, profile.PQPure, "raw")
	link := dialAs(t, s, "raw provider")
	garbage := []byte{0, 0, 0, 3, 0xa1, 0x61, 0x78}
	stalled := []byte{0, 0, 0, 10}
	for name, raw := range map[string][]byte{"not a STREAM_OPEN": garbage, "a frame never finished": stalled} {
		stream, err := s.RawStream(t.Context(), link.NodeID(), raw)
		if err != nil {
			t.Fatalf("%s: RawStream: %v", name, err)
		}
		select {
		case <-stream.Released():
		case <-time.After(5 * time.Second):
			t.Errorf("%s: the link never released the stream", name)
		}
	}
	select {
	case <-link.Done():
		t.Errorf("the link ended: %v", link.Err())
	default:
	}
}

// A long stream costs no goroutine per frame.
func TestAStreamCostsNoGoroutinePerFrame(t *testing.T) {
	w := newStreamWorld(t, "goroutines")
	w.serve(t, frame.ServerStream, func(ctx context.Context, s *stationlink.Stream) error {
		for range 500 {
			if err := s.Send([]byte("x")); err != nil {
				return err
			}
		}
		return s.Close()
	})
	before := runtime.NumGoroutine()
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	peak := 0
	for {
		event, err := recv(t, stream)
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		peak = max(peak, runtime.NumGoroutine())
		if event.Kind == stationlink.StreamEnd {
			break
		}
	}
	if grown := peak - before; grown > 20 {
		t.Errorf("goroutines grew by %d over a 500-frame stream", grown)
	}
	w.released(t)
}

// A handler that returns nil without ending its stream has it closed on both
// sides for it.
func TestAHandlerThatReturnsLeavesAClosedStream(t *testing.T) {
	w := newStreamWorld(t, "returns")
	w.serve(t, frame.ServerStream, func(_ context.Context, s *stationlink.Stream) error {
		return s.Send([]byte("only"))
	})
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	if event, err := recv(t, stream); err != nil || event.Kind != stationlink.StreamData {
		t.Fatalf("the chunk: %+v, %v", event, err)
	}
	if event, err := recv(t, stream); err != nil || event.Kind != stationlink.StreamEnd || event.Role != frame.Both {
		t.Errorf("the end: %+v, %v", event, err)
	}
	w.released(t)
}

// A bidi stream both sides end sending ends at both, and gives back the
// provider's session place.
func TestABidiStreamEndsWhenBothSidesEndSending(t *testing.T) {
	restore := stationlink.SetStreamSessionLimits(1, 1000)
	t.Cleanup(restore)
	w := newStreamWorld(t, "bidi ends")
	served := make(chan *stationlink.Stream, 2)
	w.serve(t, frame.Bidi, func(ctx context.Context, s *stationlink.Stream) error {
		served <- s
		for {
			event, err := s.Recv(ctx)
			if err != nil {
				return err
			}
			if event.Kind == stationlink.StreamEnd {
				if err := s.CloseSend(); err != nil {
					return err
				}
				<-s.Done()
				return nil
			}
		}
	})
	stream := w.open(t, frame.Bidi, cbor.Map(nil))
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	provider := <-served
	for name, s := range map[string]*stationlink.Stream{"caller": stream, "provider": provider} {
		select {
		case <-s.Done():
		case <-time.After(5 * time.Second):
			t.Errorf("the %s's stream never ended", name)
		}
	}
	w.released(t)
	next := w.open(t, frame.Bidi, cbor.Map(nil))
	_ = next.Abort("done", "")
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Error("the session place was not given back")
	}
}

// A provider that ends a session stops reading it: a peer that keeps writing
// after the provider aborted is stopped, rather than filling the link's
// buffers.
func TestAnEndedSessionStopsReading(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "stops reading")
	realm := teststation.NewRealm(t, profile.PQPure, "stops reading", "mcl-tube")
	provider := dialAs(t, s, "stopping provider")
	realm.Admit(t, s, provider.NodeID())
	if _, err := provider.Serve(t.Context(), stationlink.Offer{Realm: realm.ID, Procedure: streamProcedure, RealmKey: realm.RealmKey(),
		Stream: &stationlink.StreamOffer{Mode: frame.Bidi, Handler: func(context.Context, *stationlink.Stream) error {
			return errors.New("not today")
		}}}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	callerKey := teststation.Key(t, profile.PQPure, "raw caller")
	mode := frame.Bidi
	open, err := frame.SignStreamOpen(frame.RequestSpec{RequestID: [16]byte{7}, Realm: realm.ID, Procedure: streamProcedure,
		Target: provider.NodeID(), Deadline: uint64(time.Now().Add(time.Minute).UnixMilli()), Payload: cbor.Map(nil), Mode: &mode}, callerKey)
	if err != nil {
		t.Fatalf("SignStreamOpen: %v", err)
	}
	encoded := cbor.Encode(open)
	framed := append([]byte{byte(len(encoded) >> 24), byte(len(encoded) >> 16), byte(len(encoded) >> 8), byte(len(encoded))}, encoded...)
	raw, err := s.RawStream(t.Context(), provider.NodeID(), framed)
	if err != nil {
		t.Fatalf("RawStream: %v", err)
	}
	if !raw.KeepWriting(5 * time.Second) {
		t.Error("the provider kept reading a session it had ended")
	}
}
