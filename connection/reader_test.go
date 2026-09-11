package connection

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// fakeControl is the station's end of a session's control stream. Frames the
// test sends reach the session's reader; frames the session writes are kept,
// in order, for the test to read back. While writes are stalled, a write waits
// for the stall to lift or its write deadline to pass.
type fakeControl struct {
	inbound chan []byte
	closed  chan struct{}
	close   sync.Once

	mu            sync.Mutex
	buffered      []byte
	written       []byte
	writeDeadline time.Time
	stall         chan struct{}
	stalledWrites int
}

func newFakeControl() *fakeControl {
	return &fakeControl{inbound: make(chan []byte, 2048), closed: make(chan struct{})}
}

func (f *fakeControl) Read(p []byte) (int, error) {
	f.mu.Lock()
	if len(f.buffered) > 0 {
		n := copy(p, f.buffered)
		f.buffered = f.buffered[n:]
		f.mu.Unlock()
		return n, nil
	}
	f.mu.Unlock()
	select {
	case chunk := <-f.inbound:
		n := copy(p, chunk)
		if n < len(chunk) {
			f.mu.Lock()
			f.buffered = append(f.buffered, chunk[n:]...)
			f.mu.Unlock()
		}
		return n, nil
	case <-f.closed:
		return 0, io.EOF
	}
}

func (f *fakeControl) Write(p []byte) (int, error) {
	f.mu.Lock()
	stall, deadline := f.stall, f.writeDeadline
	if stall != nil {
		f.stalledWrites++
	}
	f.mu.Unlock()
	if stall != nil {
		var expired <-chan time.Time
		if !deadline.IsZero() {
			timer := time.NewTimer(time.Until(deadline))
			defer timer.Stop()
			expired = timer.C
		}
		select {
		case <-stall:
		case <-expired:
			return 0, writeTimeout{}
		case <-f.closed:
			return 0, io.ErrClosedPipe
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, p...)
	return len(p), nil
}

func (f *fakeControl) Close() error {
	f.close.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeControl) SetReadDeadline(time.Time) error { return nil }

func (f *fakeControl) SetWriteDeadline(t time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writeDeadline = t
	return nil
}

// writeTimeout is the error a write returns when its deadline passes.
type writeTimeout struct{}

func (writeTimeout) Error() string   { return "fake control stream: write deadline exceeded" }
func (writeTimeout) Timeout() bool   { return true }
func (writeTimeout) Temporary() bool { return true }

// stallWrites makes every write wait until the returned lift is called.
func (f *fakeControl) stallWrites() (lift func()) {
	ch := make(chan struct{})
	f.mu.Lock()
	f.stall = ch
	f.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			f.mu.Lock()
			f.stall = nil
			f.mu.Unlock()
			close(ch)
		})
	}
}

// awaitStalledWrite waits until a write is waiting on the stall.
func (f *fakeControl) awaitStalledWrite(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		n := f.stalledWrites
		f.mu.Unlock()
		if n > 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("no write ever waited on the stall")
}

func (f *fakeControl) send(t *testing.T, v cbor.Value) {
	t.Helper()
	b, err := frame.Encode(v)
	if err != nil {
		t.Fatalf("frame.Encode: %v", err)
	}
	f.inbound <- b
}

func (f *fakeControl) sent(t *testing.T) []cbor.Value {
	t.Helper()
	f.mu.Lock()
	buf := append([]byte(nil), f.written...)
	f.mu.Unlock()
	var out []cbor.Value
	for len(buf) > 0 {
		d, err := frame.Decode(buf)
		if err != nil || !d.Complete {
			t.Fatalf("the session wrote bytes that aren't whole frames (%v)", err)
		}
		out = append(out, d.Frame)
		buf = buf[d.Consumed:]
	}
	return out
}

func (f *fakeControl) sentOfType(t *testing.T, frameType string) []cbor.Value {
	t.Helper()
	var out []cbor.Value
	for _, v := range f.sent(t) {
		if frameTypeOf(v) == frameType {
			out = append(out, v)
		}
	}
	return out
}

// awaitSentOfType waits until the session has written n frames of frameType.
func (f *fakeControl) awaitSentOfType(t *testing.T, frameType string, n int) []cbor.Value {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got := f.sentOfType(t, frameType); len(got) >= n {
			return got
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the session wrote fewer than %d %s frame(s)", n, frameType)
	return nil
}

// awaitReplyTo waits for the session's RESULT or ERROR to call.
func (f *fakeControl) awaitReplyTo(t *testing.T, call cbor.Value) frame.CallResponse {
	t.Helper()
	want, _ := frame.FrameCallID(call)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, v := range f.sent(t) {
			typ := frameTypeOf(v)
			got, ok := frame.FrameCallID(v)
			if (typ == "result" || typ == "error") && ok && bytes.Equal(got, want) {
				resp, err := frame.ParseCallResponse(v)
				if err != nil {
					t.Fatalf("ParseCallResponse: %v", err)
				}
				return resp
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("the session never replied to the call")
	return frame.CallResponse{}
}

// replyTo answers a CALL the session wrote with a RESULT carrying payload.
func (f *fakeControl) replyTo(t *testing.T, call cbor.Value, payload cbor.Value) {
	t.Helper()
	info, err := frame.ParseCall(call)
	if err != nil {
		t.Fatalf("ParseCall: %v", err)
	}
	f.send(t, frame.Result(frame.NewResultSpec(info.CallID, payload, stationNode(9))))
}

func frameTypeOf(v cbor.Value) string {
	ft, _ := v.Get("frame_type")
	s, _ := ft.AsText()
	return s
}

func testRealm() []byte { return bytes.Repeat([]byte{7}, 32) }

func eventFrame(topic string, seq uint64) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("frame_type"), Val: cbor.Text("event")},
		{Key: cbor.Text("topic"), Val: cbor.Bytes([]byte(topic))},
		{Key: cbor.Text("realm"), Val: cbor.Bytes(testRealm())},
		{Key: cbor.Text("publisher"), Val: cbor.Bytes(stationNode(3))},
		{Key: cbor.Text("seq"), Val: cbor.Uint64(seq)},
		{Key: cbor.Text("payload"), Val: cbor.Text(topic)},
		{Key: cbor.Text("delivered_via"), Val: cbor.Text("fake")},
	})
}

func bareFrame(frameType string) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("frame_type"), Val: cbor.Text(frameType)}})
}

// signedCall is a CALL for procedure from caller, as a station forwards one.
func signedCall(t *testing.T, caller identity.KeyPair, procedure string, deadline time.Time) cbor.Value {
	t.Helper()
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	spec := frame.NewCallSpec(callID, procedure, testRealm(), cbor.Text("ping"), deadline.UnixMilli(), caller.NodeID())
	return frame.Sign(frame.Call(spec), caller)
}

// readingSession is a handshaked session reading a fake control stream, as
// connectOne leaves one, with its station at stationNode(9).
func readingSession(t *testing.T) (*Session, *fakeControl, identity.KeyPair) {
	t.Helper()
	id := registryIdentity(t)
	fc := newFakeControl()
	s := &Session{
		control:  &FrameStream{stream: fc},
		Station:  frame.HelloInfo{NodeID: stationNode(9)},
		identity: id.NodeID(),
		self:     id,
		done:     make(chan struct{}),
	}
	s.startReader()
	t.Cleanup(func() { _ = fc.Close() })
	return s, fc, id
}

func mustSubscribe(t *testing.T, s *Session, id identity.KeyPair, topic string) *Subscription {
	t.Helper()
	sub, err := s.Subscribe(frame.NewSubscribeSpec(topic, testRealm(), id.NodeID()), id)
	if err != nil {
		t.Fatalf("Subscribe(%s): %v", topic, err)
	}
	return sub
}

func callAsync(s *Session, id identity.KeyPair, procedure string, timeout time.Duration) <-chan error {
	done := make(chan error, 1)
	go func() {
		_, err := s.Call(procedure, testRealm(), cbor.Null(), time.Now().Add(timeout).UnixMilli(), id, timeout)
		done <- err
	}()
	return done
}

func awaitErr(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("the call never returned")
		return nil
	}
}

// roundTrip makes one call and answers it, so every frame the station sent
// before it has been through the reader.
func roundTrip(t *testing.T, s *Session, fc *fakeControl, id identity.KeyPair) {
	t.Helper()
	before := len(fc.sentOfType(t, "call"))
	done := callAsync(s, id, "sync", 2*time.Second)
	calls := fc.awaitSentOfType(t, "call", before+1)
	fc.replyTo(t, calls[before], cbor.Null())
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("round trip: %v", err)
	}
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestConcurrentCallsOnOneSessionEachGetTheirOwnReply(t *testing.T) {
	s, fc, id := readingSession(t)
	const n = 8
	results := make(chan error, n)
	for i := range n {
		go func() {
			procedure := fmt.Sprintf("echo.%d", i)
			resp, err := s.Call(procedure, testRealm(), cbor.Null(), time.Now().Add(2*time.Second).UnixMilli(), id, 2*time.Second)
			if err != nil {
				results <- err
				return
			}
			if got, _ := resp.Payload.AsText(); got != procedure {
				results <- fmt.Errorf("call %s got the reply %q", procedure, got)
				return
			}
			results <- nil
		}()
	}
	calls := fc.awaitSentOfType(t, "call", n)
	for i := len(calls) - 1; i >= 0; i-- {
		info, _ := frame.ParseCall(calls[i])
		fc.replyTo(t, calls[i], cbor.Text(info.Procedure))
	}
	for range n {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnEventArrivingDuringACallReachesItsSubscriber(t *testing.T) {
	s, fc, id := readingSession(t)
	sub := mustSubscribe(t, s, id, "news/today")
	defer sub.Close()
	done := callAsync(s, id, "slow", 2*time.Second)
	call := fc.awaitSentOfType(t, "call", 1)[0]

	fc.send(t, eventFrame("news/today", 1))
	evt, err := sub.Recv(time.Second)
	if err != nil || evt.Topic != "news/today" {
		t.Fatalf("Recv = (%v, %v), want the event on news/today while the call waits", evt, err)
	}
	fc.replyTo(t, call, cbor.Null())
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("Call: %v", err)
	}
}

func TestServingACallWhileCallingOnTheSameSession(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	lookup := func(_ []byte, procedure string) (CallHandler, bool) {
		return func(cbor.Value) (cbor.Value, error) { return cbor.Text("served " + procedure), nil }, true
	}
	served := make(chan error, 1)
	go func() { served <- s.ServeOneCall(lookup, id, 2*time.Second) }()
	calling := callAsync(s, id, "outbound", 2*time.Second)
	outbound := fc.awaitSentOfType(t, "call", 1)[0]

	inbound := signedCall(t, caller, "inbound", time.Now().Add(2*time.Second))
	fc.send(t, inbound)
	if err := awaitErr(t, served); err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}
	if resp := fc.awaitReplyTo(t, inbound); resp.IsError {
		t.Fatalf("the inbound call got an error reply: %+v", resp)
	} else if got, _ := resp.Payload.AsText(); got != "served inbound" {
		t.Fatalf("the inbound call's reply = %q, want \"served inbound\"", got)
	}
	fc.replyTo(t, outbound, cbor.Null())
	if err := awaitErr(t, calling); err != nil {
		t.Fatalf("Call: %v", err)
	}
}

func TestTwoSubscribersWithDifferentTopicsEachGetOnlyTheirEvents(t *testing.T) {
	s, fc, id := readingSession(t)
	a := mustSubscribe(t, s, id, "a/b")
	b := mustSubscribe(t, s, id, "c/d")

	fc.send(t, eventFrame("a/b", 1))
	if evt, err := a.Recv(time.Second); err != nil || evt.Topic != "a/b" {
		t.Fatalf("the a/b subscriber's Recv = (%v, %v), want its event", evt, err)
	}
	if evt, err := b.Recv(100 * time.Millisecond); !errors.Is(err, ErrRecvTimeout) {
		t.Fatalf("the c/d subscriber's Recv = (%v, %v), want ErrRecvTimeout", evt, err)
	}
}

func TestAWildcardSubscriptionMatchesExactlyOneSegment(t *testing.T) {
	s, fc, id := readingSession(t)
	sub := mustSubscribe(t, s, id, "org/*/x")

	fc.send(t, eventFrame("org/y/z/x", 1))
	fc.send(t, eventFrame("org/x", 2))
	fc.send(t, eventFrame("org/y/x", 3))
	evt, err := sub.Recv(time.Second)
	if err != nil || evt.Topic != "org/y/x" {
		t.Fatalf("Recv = (%v, %v), want only the event on org/y/x", evt, err)
	}
	if evt, err := sub.Recv(100 * time.Millisecond); !errors.Is(err, ErrRecvTimeout) {
		t.Fatalf("a second Recv = (%v, %v), want ErrRecvTimeout", evt, err)
	}
}

func TestAStalledEventConsumerDoesNotStallCallReplies(t *testing.T) {
	s, fc, id := readingSession(t)
	mustSubscribe(t, s, id, "busy")
	for i := range 2 * subscriptionQueue {
		fc.send(t, eventFrame("busy", uint64(i)))
	}
	done := callAsync(s, id, "ping", 2*time.Second)
	fc.replyTo(t, fc.awaitSentOfType(t, "call", 1)[0], cbor.Null())
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("Call behind a consumer that never reads: %v", err)
	}
}

func TestAnOverflowingEventConsumerEndsWithAnOverflowErrorAndTheSessionStaysUp(t *testing.T) {
	s, fc, id := readingSession(t)
	sub := mustSubscribe(t, s, id, "flood")
	for i := range subscriptionQueue + 10 {
		fc.send(t, eventFrame("flood", uint64(i)))
	}
	roundTrip(t, s, fc, id)

	for i := range subscriptionQueue {
		evt, err := sub.Recv(time.Second)
		if err != nil || evt.Seq != uint64(i) {
			t.Fatalf("Recv #%d = (seq %d, %v), want the queued event with seq %d", i, evt.Seq, err, i)
		}
	}
	if _, err := sub.Recv(time.Second); !errors.Is(err, ErrConsumerOverflow) {
		t.Fatalf("Recv after the queued events = %v, want ErrConsumerOverflow", err)
	}
	roundTrip(t, s, fc, id)
}

func TestAnOverflowingCallQueueAnswersTheExtraCallAndKeepsServing(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	var first, extra cbor.Value
	for i := range inboundCallQueue + 1 {
		c := signedCall(t, caller, fmt.Sprintf("p.%d", i), time.Now().Add(5*time.Second))
		switch i {
		case 0:
			first = c
		case inboundCallQueue:
			extra = c
		}
		fc.send(t, c)
	}

	resp := fc.awaitReplyTo(t, extra)
	if !resp.IsError || resp.Code != uint8(bolt4.TemporaryRelayFailure) {
		t.Fatalf("the extra call's reply = %+v, want ERROR temporary_relay_failure", resp)
	}
	if err := s.ServeOneCall(echoLookup, id, time.Second); err != nil {
		t.Fatalf("ServeOneCall after the overflow: %v", err)
	}
	if resp := fc.awaitReplyTo(t, first); resp.IsError {
		t.Fatalf("the first queued call's reply = %+v, want its RESULT", resp)
	}
	if n := len(fc.sentOfType(t, "error")); n != 1 {
		t.Fatalf("error replies = %d, want only the extra call's", n)
	}
}

func TestAGoodbyeFromTheStationFailsPendingCallsAndEndsTheSession(t *testing.T) {
	s, fc, id := readingSession(t)
	done := callAsync(s, id, "pending", 5*time.Second)
	fc.awaitSentOfType(t, "call", 1)

	detail := "maintenance"
	fc.send(t, frame.Goodbye("shutdown", &detail))
	err := awaitErr(t, done)
	var goodbye *GoodbyeError
	if !errors.Is(err, ErrSessionEnded) || !errors.As(err, &goodbye) || goodbye.Reason != "shutdown" || goodbye.Detail != "maintenance" {
		t.Fatalf("the pending call = %v, want ErrSessionEnded with the station's goodbye", err)
	}
	if err := awaitErr(t, callAsync(s, id, "after", time.Second)); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("a call after the goodbye = %v, want ErrSessionEnded", err)
	}
}

func TestAnOverflowedSubscriptionKeepsTheStationSubscribedUntilItIsClosed(t *testing.T) {
	s, fc, id := readingSession(t)
	sub := mustSubscribe(t, s, id, "flood")
	for i := range subscriptionQueue + 1 {
		fc.send(t, eventFrame("flood", uint64(i)))
	}
	publishes := len(fc.sentOfType(t, "publish"))
	roundTrip(t, s, fc, id)
	// The round trip's rpc.completed_v1 fact is handed to the writer after
	// the overflow, so once it is written nothing handed over before it is
	// still waiting.
	fc.awaitSentOfType(t, "publish", publishes+2)

	for range subscriptionQueue {
		if _, err := sub.Recv(time.Second); err != nil {
			t.Fatalf("Recv of a queued event: %v", err)
		}
	}
	_, err := sub.Recv(time.Second)
	if !errors.Is(err, ErrConsumerOverflow) {
		t.Fatalf("Recv after the queued events = %v, want ErrConsumerOverflow", err)
	}
	if !strings.Contains(err.Error(), "Close") {
		t.Fatalf("overflow error %q does not tell the subscriber to call Close", err)
	}
	if n := len(fc.sentOfType(t, "unsubscribe")); n != 0 {
		t.Fatalf("UNSUBSCRIBE frames after the overflow = %d, want 0 until the subscription is closed", n)
	}

	if err := sub.Close(); err != nil {
		t.Fatalf("Close after the overflow: %v", err)
	}
	if n := len(fc.sentOfType(t, "unsubscribe")); n != 1 {
		t.Fatalf("UNSUBSCRIBE frames after closing the overflowed last subscription = %d, want 1", n)
	}
}

func TestAFrameThatCannotBeDecodedEndsTheSession(t *testing.T) {
	s, fc, _ := readingSession(t)
	// A length prefix past the frame cap: the stream cannot be read past it.
	fc.inbound <- []byte{0xff, 0xff, 0xff, 0xff}

	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("Done() did not close after a frame that cannot be decoded")
	}
	if err := s.Publish(frame.NewPublishSpec("after", testRealm(), s.identity, 1, cbor.Null(), 0), s.self); !errors.Is(err, ErrSessionEnded) {
		t.Fatalf("Publish after the session ended = %v, want ErrSessionEnded", err)
	}
}

func TestACallOnASessionThatHasEndedReportsItWasNotSent(t *testing.T) {
	s, fc, id := readingSession(t)
	detail := "maintenance"
	fc.send(t, frame.Goodbye("shutdown", &detail))

	deadline := time.Now().Add(2 * time.Second)
	var err error
	for time.Now().Before(deadline) {
		if err = awaitErr(t, callAsync(s, id, "after.goodbye", 50*time.Millisecond)); errors.Is(err, ErrSessionEnded) {
			break
		}
	}
	if !errors.Is(err, ErrSessionEnded) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("Call after the session ended = %v, want ErrSessionEnded and ErrNotSent", err)
	}
}

func TestACallWaitingForTheWriteLockWhenTheSessionEndsReportsItWasNotSent(t *testing.T) {
	s, fc, id := readingSession(t)
	s.sendTimeout = 5 * time.Second
	lift := fc.stallWrites()
	t.Cleanup(lift)
	go func() { _ = s.Publish(frame.NewPublishSpec("stalls", testRealm(), id.NodeID(), 1, cbor.Null(), 0), id) }()
	fc.awaitStalledWrite(t)

	started := time.Now()
	done := callAsync(s, id, "waits.for.the.lock", 3*time.Second)
	time.Sleep(50 * time.Millisecond) // lets the call reach the write lock
	detail := "maintenance"
	fc.send(t, frame.Goodbye("shutdown", &detail))

	err := awaitErr(t, done)
	if !errors.Is(err, ErrSessionEnded) || !errors.Is(err, ErrNotSent) {
		t.Fatalf("Call waiting for the write lock = %v, want ErrSessionEnded and ErrNotSent", err)
	}
	if waited := time.Since(started); waited > 1500*time.Millisecond {
		t.Fatalf("Call returned after %s, want promptly when the session ended, not at its timeout", waited)
	}
}

func TestALinkCallPublishesNoRPCFacts(t *testing.T) {
	s, fc, id := readingSession(t)
	publishes := len(fc.sentOfType(t, "publish"))
	calls := len(fc.sentOfType(t, "call"))

	done := make(chan error, 1)
	go func() {
		spec := frame.NewCallSpec(nil, "_macula.ping", make([]byte, 32), cbor.Null(), time.Now().Add(time.Second).UnixMilli(), id.NodeID())
		_, err := s.LinkCall(spec, id, time.Second)
		done <- err
	}()
	sent := fc.awaitSentOfType(t, "call", calls+1)
	fc.replyTo(t, sent[calls], cbor.Null())
	if err := awaitErr(t, done); err != nil {
		t.Fatalf("LinkCall: %v", err)
	}

	// The round trip's own two facts are handed to the writer after anything
	// the link call handed over, so once they are written nothing is pending.
	roundTrip(t, s, fc, id)
	fc.awaitSentOfType(t, "publish", publishes+2)
	if n := len(fc.sentOfType(t, "publish")) - publishes; n != 2 {
		t.Fatalf("PUBLISH frames = %d, want only the round trip's 2 RPC facts", n)
	}
}

func TestAnUnroutedFrameIsCountedByType(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))

	fc.send(t, bareFrame("stream_data"))
	fc.send(t, bareFrame("stream_data"))
	fc.send(t, bareFrame("advertise"))
	roundTrip(t, s, fc, id)

	counts := s.Unrouted()
	if counts["stream_data"] != 2 || counts["advertise"] != 1 {
		t.Fatalf("Unrouted() = %v, want stream_data 2 and advertise 1", counts)
	}
	if got := strings.Count(logged.String(), "macula: dropped 1 unrouted stream_data frame(s) in the last minute"); got != 1 {
		t.Fatalf("log lines for stream_data = %d, want 1 in the minute; log:\n%s", got, logged.String())
	}
}

func TestAHelloAfterTheHandshakeEndsTheSession(t *testing.T) {
	s, fc, id := readingSession(t)
	done := callAsync(s, id, "pending", 5*time.Second)
	fc.awaitSentOfType(t, "call", 1)

	fc.send(t, bareFrame("hello"))
	if err := awaitErr(t, done); !errors.Is(err, ErrSessionEnded) || !errors.Is(err, ErrProtocolViolation) {
		t.Fatalf("the pending call = %v, want ErrSessionEnded from a protocol violation", err)
	}
}

func TestClosingTheLastSubscriptionForATopicUnsubscribes(t *testing.T) {
	s, fc, id := readingSession(t)
	first := mustSubscribe(t, s, id, "shared")
	second := mustSubscribe(t, s, id, "shared")
	if n := len(fc.sentOfType(t, "subscribe")); n != 1 {
		t.Fatalf("SUBSCRIBE frames = %d, want 1 for two subscriptions to one topic", n)
	}

	_ = first.Close()
	if n := len(fc.sentOfType(t, "unsubscribe")); n != 0 {
		t.Fatalf("UNSUBSCRIBE frames after closing one of two = %d, want 0", n)
	}
	_ = second.Close()
	if n := len(fc.sentOfType(t, "unsubscribe")); n != 1 {
		t.Fatalf("UNSUBSCRIBE frames after closing the last = %d, want 1", n)
	}
}

// Waiting for the write lock is bounded by the caller's own deadline: that
// caller times out, its frame was never sent, and the session goes on.
func TestACallThatCannotGetTheWriteLockInTimeTimesOutAndTheSessionStaysUp(t *testing.T) {
	s, fc, id := readingSession(t)
	s.sendTimeout = 5 * time.Second
	lift := fc.stallWrites()
	publishing := make(chan error, 1)
	go func() {
		publishing <- s.Publish(frame.NewPublishSpec("t", testRealm(), id.NodeID(), 1, cbor.Null(), time.Now().UnixMilli()), id)
	}()
	fc.awaitStalledWrite(t)

	err := awaitErr(t, callAsync(s, id, "quick", 100*time.Millisecond))
	if !errors.Is(err, ErrCallTimeout) || !errors.Is(err, ErrNotSent) || errors.Is(err, ErrSessionEnded) {
		t.Fatalf("Call = %v, want ErrCallTimeout with ErrNotSent, leaving the session up", err)
	}
	lift()
	if err := awaitErr(t, publishing); err != nil {
		t.Fatalf("the publish once the stall lifted: %v", err)
	}
	roundTrip(t, s, fc, id)
}

// A write stuck past the session send timeout may have left a frame half
// written, so it ends the session.
func TestAWriteStalledPastTheSendTimeoutEndsTheSession(t *testing.T) {
	s, fc, id := readingSession(t)
	s.sendTimeout = 100 * time.Millisecond
	fc.stallWrites()

	err := s.Publish(frame.NewPublishSpec("t", testRealm(), id.NodeID(), 1, cbor.Null(), time.Now().UnixMilli()), id)
	if !errors.Is(err, ErrSendTimeout) {
		t.Fatalf("Publish = %v, want ErrSendTimeout", err)
	}
	if err := awaitErr(t, callAsync(s, id, "after", time.Second)); !errors.Is(err, ErrSessionEnded) || !errors.Is(err, ErrSendTimeout) {
		t.Fatalf("a call after the stalled write = %v, want ErrSessionEnded from ErrSendTimeout", err)
	}
}

// The reader never waits on a write: with writes stalled, an overflowing
// call's error reply can't go out, and events are still delivered.
func TestTheReaderKeepsDeliveringWhileAWriteIsStalled(t *testing.T) {
	s, fc, id := readingSession(t)
	s.sendTimeout = 5 * time.Second
	sub := mustSubscribe(t, s, id, "live")
	lift := fc.stallWrites()
	defer lift()
	caller := registryIdentity(t)
	for i := range inboundCallQueue + 4 {
		fc.send(t, signedCall(t, caller, fmt.Sprintf("p.%d", i), time.Now().Add(5*time.Second)))
	}

	fc.send(t, eventFrame("live", 1))
	if evt, err := sub.Recv(time.Second); err != nil || evt.Topic != "live" {
		t.Fatalf("Recv with writes stalled = (%v, %v), want the event", evt, err)
	}
}

func echoLookup(_ []byte, procedure string) (CallHandler, bool) {
	return func(cbor.Value) (cbor.Value, error) { return cbor.Text("served " + procedure), nil }, true
}

// A Call whose timeout passes while its frame is being written may have
// reached the station: its error doesn't say the frame was not sent, the
// session goes on, and a RESULT that arrives later is counted as unrouted.
func TestACallTimingOutWhileItsFrameIsBeingWrittenReportsItMayHaveBeenSent(t *testing.T) {
	s, fc, id := readingSession(t)
	s.sendTimeout = 5 * time.Second
	lift := fc.stallWrites()

	err := awaitErr(t, callAsync(s, id, "slow-write", 100*time.Millisecond))
	if !errors.Is(err, ErrCallTimeout) || errors.Is(err, ErrNotSent) || errors.Is(err, ErrSessionEnded) {
		t.Fatalf("Call = %v, want ErrCallTimeout that doesn't claim the frame was unsent", err)
	}
	lift()
	call := fc.awaitSentOfType(t, "call", 1)[0]
	fc.replyTo(t, call, cbor.Null())
	roundTrip(t, s, fc, id)
	if n := s.Unrouted()["result"]; n != 1 {
		t.Fatalf("unrouted results = %d, want the late reply counted", n)
	}
}

func TestAnInboundCallNotSignedByItsCallerIsDropped(t *testing.T) {
	s, fc, id := readingSession(t)
	caller, other := registryIdentity(t), registryIdentity(t)
	callID := make([]byte, 16)
	_, _ = rand.Read(callID)
	spec := frame.NewCallSpec(callID, "p", testRealm(), cbor.Null(), time.Now().Add(5*time.Second).UnixMilli(), caller.NodeID())
	fc.send(t, frame.Sign(frame.Call(spec), other))

	if err := s.ServeOneCall(echoLookup, id, 200*time.Millisecond); !errors.Is(err, ErrServeOneCallTimeout) {
		t.Fatalf("ServeOneCall = %v, want ErrServeOneCallTimeout: a call signed by someone else is never served", err)
	}
	if n := len(fc.sentOfType(t, "result")) + len(fc.sentOfType(t, "error")); n != 0 {
		t.Fatalf("replies = %d, want none", n)
	}
}

func TestAnUnsignedInboundCallIsDropped(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	callID := make([]byte, 16)
	_, _ = rand.Read(callID)
	spec := frame.NewCallSpec(callID, "p", testRealm(), cbor.Null(), time.Now().Add(5*time.Second).UnixMilli(), caller.NodeID())
	fc.send(t, frame.Call(spec))

	if err := s.ServeOneCall(echoLookup, id, 200*time.Millisecond); !errors.Is(err, ErrServeOneCallTimeout) {
		t.Fatalf("ServeOneCall = %v, want ErrServeOneCallTimeout: an unsigned call is never served", err)
	}
	if n := len(fc.sentOfType(t, "result")) + len(fc.sentOfType(t, "error")); n != 0 {
		t.Fatalf("replies = %d, want none", n)
	}
}

// A queued CALL past its deadline_ms is still served, as the Erlang provider
// serves one.
func TestAQueuedCallPastItsDeadlineIsStillServed(t *testing.T) {
	s, fc, id := readingSession(t)
	caller := registryIdentity(t)
	expired := signedCall(t, caller, "late", time.Now().Add(-time.Second))
	fc.send(t, expired)

	if err := s.ServeOneCall(echoLookup, id, time.Second); err != nil {
		t.Fatalf("ServeOneCall: %v", err)
	}
	if resp := fc.awaitReplyTo(t, expired); resp.IsError {
		t.Fatalf("the expired call's reply = %+v, want its RESULT", resp)
	}
}

func TestASessionEndIsLoggedOnceWithItsReason(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	detail := fmt.Sprintf("maintenance window %d", time.Now().UnixNano())
	fc.send(t, frame.Goodbye("shutdown", &detail))
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not end after the station's GOODBYE")
	}
	_ = s.Close("normal", nil, id)

	lines := linesWith(logged.String(), "macula: session ended")
	if len(lines) != 1 {
		t.Fatalf("session-end lines = %d, want 1; log:\n%s", len(lines), logged.String())
	}
	for _, want := range []string{detail, hex.EncodeToString(s.Station.NodeID), hex.EncodeToString(s.identity), "level=WARN"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("session-end line %q lacks %q", lines[0], want)
		}
	}

	closed, _, closedID := readingSession(t)
	closedLog := &lockedBuffer{}
	closed.SetLogger(slog.New(slog.NewTextHandler(closedLog, nil)))
	_ = closed.Close("normal", nil, closedID)
	if lines := linesWith(closedLog.String(), "macula: session ended"); len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") {
		t.Fatalf("session-end lines for a local Close = %q, want exactly one at level INFO", lines)
	}
}

// linesWith returns the lines of log that contain text.
func linesWith(log, text string) []string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, text) {
			out = append(out, line)
		}
	}
	return out
}
