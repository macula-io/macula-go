package pool

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

var (
	errNoMoreScriptedSessions = errors.New("pool_test: dialer has no more scripted sessions for this target")
	errNotSubscribeFrame      = errors.New("pool_test: frame is not a subscribe frame")
)

// -- fakeSession: an in-memory sessionLike, driven entirely by the test,
// so respawn/replay/dedup/timeout logic can be exercised deterministically
// without a live QUIC connection. Mirrors how connection/serve_ucan_test.go
// already tests pure dispatch logic with a nil *Session at a smaller scale.

type fakeTimeoutErr struct{}

func (fakeTimeoutErr) Error() string   { return "fake: recv timeout" }
func (fakeTimeoutErr) Timeout() bool   { return true }
func (fakeTimeoutErr) Temporary() bool { return true }

type fakeSession struct {
	recv chan cbor.Value
	done chan struct{}

	// blockSend, when non-nil, makes every SendAny block until it's
	// closed -- simulates quic-go's Write parking on flow-control
	// credit, per the R1 finding this file's overflow test reproduces.
	blockSend chan struct{}

	mu   sync.Mutex
	sent []cbor.Value
}

func newFakeSession() *fakeSession {
	return &fakeSession{recv: make(chan cbor.Value, 16), done: make(chan struct{})}
}

func (f *fakeSession) RecvAny(deadline time.Time) (cbor.Value, error) {
	timeout := time.Until(deadline)
	if timeout < 0 {
		timeout = 0
	}
	select {
	case v := <-f.recv:
		return v, nil
	case <-f.done:
		return cbor.Value{}, fakeTimeoutErr{}
	case <-time.After(timeout):
		return cbor.Value{}, fakeTimeoutErr{}
	}
}

func (f *fakeSession) SendAny(v cbor.Value) error {
	if f.blockSend != nil {
		select {
		case <-f.blockSend:
		case <-f.done:
			return fakeTimeoutErr{}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, v)
	return nil
}

func (f *fakeSession) Sent() []cbor.Value {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cbor.Value, len(f.sent))
	copy(out, f.sent)
	return out
}

func (f *fakeSession) Done() <-chan struct{} { return f.done }

// Close always returns immediately, deliberately not honoring
// blockSend -- this models connection.Session.Close's contract (bounded
// by its own internal write deadline, see connection.go's
// closeSendTimeout) rather than the bug that contract was fixed to
// close. The real Session.Close's bounded-write behavior against an
// actual stalled QUIC peer is exercised directly by
// connection.TestSendFrameIsBoundedByWriteDeadline (a loopback test,
// no macula protocol needed) -- this fake's job is only to let a
// pool-level test exercise what the pool does GIVEN a well-behaved
// Close, not to re-prove the primitive it depends on.
func (f *fakeSession) Close(string, *string, identity.KeyPair) error { return nil }

func (f *fakeSession) RemoteAddr() string { return "fake" }

// kill simulates the connection dying out from under the actor -- the
// same signal Session.Done() gives on a real dropped/closed connection.
func (f *fakeSession) kill() { close(f.done) }

// fakeDialer hands out a scripted sequence of sessions, one per Connect
// attempt, keyed by host:port -- lets a test control exactly which
// (possibly multiple, across respawns) fake session a given link dials
// into, and count how many times each target was dialed.
type fakeDialer struct {
	mu      sync.Mutex
	scripts map[string][]*fakeSession // host:port -> sessions to hand out in order
	dials   map[string]int
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{scripts: make(map[string][]*fakeSession), dials: make(map[string]int)}
}

func (d *fakeDialer) script(host string, port uint16, sessions ...*fakeSession) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scripts[linkKey(host, port)] = sessions
}

func (d *fakeDialer) dialCount(host string, port uint16) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials[linkKey(host, port)]
}

func (d *fakeDialer) dial(_ context.Context, host string, port uint16, _ transport.Trust, _ identity.KeyPair) (dialResult, error) {
	key := linkKey(host, port)
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.dials[key]
	d.dials[key] = n + 1
	sessions := d.scripts[key]
	if n >= len(sessions) {
		return dialResult{}, errNoMoreScriptedSessions
	}
	return dialResult{session: sessions[n], nodeID: []byte("fake-node-id"), remote: "fake"}, nil
}

func testIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func rawEventFrame(t *testing.T, realm, publisher []byte, topic string, seq uint64, payload cbor.Value) cbor.Value {
	t.Helper()
	if len(realm) != 32 || len(publisher) != 32 {
		t.Fatalf("realm/publisher must be 32 bytes")
	}
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("frame_type"), Val: cbor.Text("event")},
		{Key: cbor.Text("topic"), Val: cbor.Bytes([]byte(topic))},
		{Key: cbor.Text("realm"), Val: cbor.Bytes(realm)},
		{Key: cbor.Text("publisher"), Val: cbor.Bytes(publisher)},
		{Key: cbor.Text("seq"), Val: cbor.Uint64(seq)},
		{Key: cbor.Text("payload"), Val: payload},
		{Key: cbor.Text("delivered_via"), Val: cbor.Text("fake")},
	})
}

func fill32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}

// -- dedup table: pure logic, no goroutines.

func TestDedupTableCollisionsAreByContentNotAllocation(t *testing.T) {
	d := newDedupTable()
	now := time.Now()

	realmA := []byte("realm-one")
	realmACopy := append([]byte(nil), realmA...) // a SEPARATE allocation, same bytes
	pub := []byte("publisher")

	k1 := newDedupKey(realmA, pub, 1, "topic")
	if d.CheckAndMark(k1, now) {
		t.Fatalf("first sighting reported as duplicate")
	}

	k2 := newDedupKey(realmACopy, pub, 1, "topic")
	if !d.CheckAndMark(k2, now) {
		t.Fatalf("same content from a different byte-slice allocation did not collide")
	}

	k3 := newDedupKey(realmA, pub, 1, "other-topic")
	if d.CheckAndMark(k3, now) {
		t.Fatalf("different topic incorrectly collided -- this is the exact bug shape (Realm,Publisher,Seq) without Topic had")
	}

	k4 := newDedupKey(realmA, pub, 2, "topic")
	if d.CheckAndMark(k4, now) {
		t.Fatalf("different seq incorrectly collided")
	}
}

func TestDedupTableSweepRemovesOnlyStaleEntries(t *testing.T) {
	d := newDedupTable()
	base := time.Now()

	old := newDedupKey([]byte("r"), []byte("p"), 1, "t")
	fresh := newDedupKey([]byte("r"), []byte("p"), 2, "t")

	d.CheckAndMark(old, base)
	d.CheckAndMark(fresh, base.Add(50*time.Second))

	d.Sweep(base.Add(60*time.Second), 30*time.Second)

	if d.Len() != 1 {
		t.Fatalf("expected exactly 1 entry to survive the sweep, got %d", d.Len())
	}
	if d.CheckAndMark(old, base.Add(60*time.Second)) {
		t.Fatalf("swept entry should read as new (not a duplicate) on the next sighting")
	}
}

// -- Pool integration, driven by fakeDialer/fakeSession: respawn, replay, dedup, call timeout.

func testOpts(id identity.KeyPair, dial dialFunc) Opts {
	return Opts{
		Identity:       id,
		Trust:          transport.WebPKI{},
		RespawnDelay:   20 * time.Millisecond, // fast, deterministic backoff for tests
		ConnectTimeout: time.Second,
		dial:           dial,
	}
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func TestSubscribeReplaysOntoRespawnedLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s1 := newFakeSession()
	s2 := newFakeSession()
	dialer.script("station.example", 4433, s1, s2)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0xAA)
	var mu sync.Mutex
	var delivered []string
	p.Subscribe(realm, "topic.one", func(_ []byte, topic string, _ cbor.Value) {
		mu.Lock()
		delivered = append(delivered, topic)
		mu.Unlock()
	})

	waitFor(t, time.Second, func() bool { return len(subscribeFrames(s1.Sent())) == 1 })

	// Kill the first session -- the pool must respawn and REPLAY the
	// tracked subscription onto the fresh one, without the caller doing
	// anything.
	s1.kill()

	waitFor(t, time.Second, func() bool { return len(subscribeFrames(s2.Sent())) == 1 })

	got := subscribeFrames(s2.Sent())[0]
	spec, err := parseSubscribeTopic(got)
	if err != nil {
		t.Fatalf("parse replayed SUBSCRIBE: %v", err)
	}
	if spec != "topic.one" {
		t.Fatalf("replayed SUBSCRIBE topic = %q, want %q", spec, "topic.one")
	}

	if dialer.dialCount("station.example", 4433) != 2 {
		t.Fatalf("expected exactly 2 dial attempts (initial + respawn), got %d", dialer.dialCount("station.example", 4433))
	}

	// Deliver an EVENT on the NEW session and confirm the original
	// handler (registered before the respawn) still fires.
	s2.recv <- rawEventFrame(t, realm, fill32(0xBB), "topic.one", 1, cbor.Text("hello"))
	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(delivered) == 1
	})
}

func TestEventDeliveredExactlyOnceDespiteDuplicateFrames(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s1 := newFakeSession()
	dialer.script("station.example", 4433, s1)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0xCC)
	publisher := fill32(0xDD)
	var count int
	var mu sync.Mutex
	p.Subscribe(realm, "topic.dup", func(_ []byte, _ string, _ cbor.Value) {
		mu.Lock()
		count++
		mu.Unlock()
	})
	waitFor(t, time.Second, func() bool { return len(subscribeFrames(s1.Sent())) == 1 })

	evt := rawEventFrame(t, realm, publisher, "topic.dup", 42, cbor.Text("x"))
	s1.recv <- evt
	s1.recv <- evt // the exact same (realm, publisher, seq, topic) again -- e.g. relayed by more than one hop

	time.Sleep(100 * time.Millisecond) // let both drain
	mu.Lock()
	defer mu.Unlock()
	if count != 1 {
		t.Fatalf("handler invoked %d times, want exactly 1 (dedup should have suppressed the second)", count)
	}
}

func TestPanickingHandlerDoesNotStopOtherDelivery(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s1 := newFakeSession()
	dialer.script("station.example", 4433, s1)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0x99)
	publisher := fill32(0x88)

	p.Subscribe(realm, "topic.panics", func(_ []byte, _ string, _ cbor.Value) {
		panic("boom")
	})

	var mu sync.Mutex
	var gotSecond bool
	p.Subscribe(realm, "topic.fine", func(_ []byte, _ string, _ cbor.Value) {
		mu.Lock()
		gotSecond = true
		mu.Unlock()
	})
	waitFor(t, time.Second, func() bool { return len(subscribeFrames(s1.Sent())) == 2 })

	s1.recv <- rawEventFrame(t, realm, publisher, "topic.panics", 1, cbor.Text("x"))
	s1.recv <- rawEventFrame(t, realm, publisher, "topic.fine", 2, cbor.Text("y"))

	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotSecond
	})
	// Reaching here at all (not a crashed test binary) is itself part of
	// what this test asserts.
}

func TestCallFallsThroughToNextConnectedLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	dead := newFakeSession() // never answers -- Call must not get stuck on it
	live := newFakeSession()
	dialer.script("dead.example", 4433, dead)
	dialer.script("live.example", 4433, live)

	p, err := Connect(context.Background(), []Seed{{Host: "dead.example", Port: 4433}, {Host: "live.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 2 })

	// Auto-reply on the "live" session: whatever CALL arrives, answer
	// with a RESULT for its call_id.
	go func() {
		for {
			select {
			case <-live.done:
				return
			default:
			}
			frames := live.Sent()
			if len(frames) == 0 {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			callID, ok := frame.FrameCallID(frames[len(frames)-1])
			if !ok {
				continue
			}
			live.recv <- frame.Result(frame.NewResultSpec(callID, cbor.Text("ok"), fill32(0x01)))
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, err := p.Call(ctx, fill32(0xEE), "some.procedure", cbor.Null(), time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if resp.IsError {
		t.Fatalf("Call returned an error response: code=%d name=%s", resp.Code, resp.Name)
	}
	if txt, _ := resp.Payload.AsText(); txt != "ok" {
		t.Fatalf("Call payload = %v, want %q", resp.Payload, "ok")
	}
}

func TestCallTimeoutDoesNotLeakPendingEntry(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession() // never answers
	dialer.script("station.example", 4433, s)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	ctx := context.Background()
	_, err = p.Call(ctx, fill32(0x01), "never.answers", cbor.Null(), 50*time.Millisecond)
	if err != errCallTimeout {
		t.Fatalf("Call error = %v, want errCallTimeout", err)
	}

	a := p.connectedActors()[0]
	waitFor(t, time.Second, func() bool {
		n, err := a.pendingCount(context.Background())
		return err == nil && n == 0
	})
}

// TestStalledWriterRespawnsInsteadOfWedging directly reproduces the R1
// finding: a stalled peer (SendAny never returning, e.g. quic-go's
// Write parked on flow-control credit) must not wedge the actor's
// dispatch loop forever. The FIRST implementation of this package
// blocked a plain enqueue helper directly from inside the dispatch
// loop, selecting against a.done for a way out -- but a.done only
// closes when run() itself returns, and run() can't reach that close
// while it's the one stuck blocked in enqueue. This test would hang
// (and eventually time out the whole `go test` run) against that
// version; against the current one, the actor detects its outbox
// exceeding outboxCap and returns a fatal error, and the link
// respawns normally.
func TestStalledWriterRespawnsInsteadOfWedging(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	stalled := newFakeSession()
	stalled.blockSend = make(chan struct{}) // never closed -- SendAny never returns
	fresh := newFakeSession()
	dialer.script("station.example", 4433, stalled, fresh)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0x77)
	deadline := time.Now().Add(5 * time.Second)
	for i := 0; i < outboxCap*2+8 && time.Now().Before(deadline); i++ {
		_ = p.Publish(realm, "overflow.topic", cbor.Uint64(uint64(i))) // errors once the link dies mid-loop -- fine, ignored
	}

	waitFor(t, 5*time.Second, func() bool { return dialer.dialCount("station.example", 4433) == 2 })
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	a := p.connectedActors()[0]
	if a.session != sessionLike(fresh) {
		t.Fatalf("connected actor is not using the respawned session")
	}
}

func TestConnectRejectsZeroValueIdentity(t *testing.T) {
	dialer := newFakeDialer()
	_, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, Opts{
		Trust: transport.WebPKI{},
		dial:  dialer.dial,
	})
	if err == nil {
		t.Fatalf("Connect with a zero-value Identity should fail, not panic later on a background goroutine")
	}
}

func TestPublishRejectsBadPayloadWithoutTouchingAnyActor(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	dup := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("dup"), Val: cbor.Uint64(1)},
		{Key: cbor.Text("dup"), Val: cbor.Uint64(2)},
	})
	if err := p.Publish(fill32(0x01), "some.topic", dup); err == nil {
		t.Fatalf("Publish with a duplicate-key payload should be rejected, got nil error")
	}
	if len(s.Sent()) != 0 {
		t.Fatalf("a rejected payload must never reach the wire, got %d frames sent", len(s.Sent()))
	}
}

func TestCallRejectsBadPayloadWithoutTouchingAnyActor(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	big := make([]byte, 17_000_000)
	_, err = p.Call(context.Background(), fill32(0x01), "some.procedure", cbor.Bytes(big), time.Second)
	if err == nil {
		t.Fatalf("Call with an oversized payload should be rejected, got nil error")
	}
	if len(s.Sent()) != 0 {
		t.Fatalf("a rejected payload must never reach the wire, got %d frames sent", len(s.Sent()))
	}
}

func TestOnLinkEventFiresWithAnErrorOnAFailedDial(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer() // no script registered -- every dial attempt fails

	var mu sync.Mutex
	var gotErrorEvent bool
	opts := testOpts(id, dialer.dial)
	opts.OnLinkEvent = func(_ string, up bool, err error) {
		mu.Lock()
		defer mu.Unlock()
		if !up && err != nil {
			gotErrorEvent = true
		}
	}

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotErrorEvent
	})
}

func TestOnLinkEventFiresUpOnSuccessfulConnect(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s)

	var mu sync.Mutex
	var gotUp bool
	opts := testOpts(id, dialer.dial)
	opts.OnLinkEvent = func(_ string, up bool, _ error) {
		mu.Lock()
		defer mu.Unlock()
		if up {
			gotUp = true
		}
	}

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotUp
	})
}

func TestLivenessProbeRespawnsAfterConsecutiveMisses(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	silent := newFakeSession() // never answers _macula.ping
	fresh := newFakeSession()
	dialer.script("station.example", 4433, silent, fresh)

	opts := testOpts(id, dialer.dial)
	opts.LivenessInterval = 30 * time.Millisecond
	opts.LivenessMaxMisses = 2

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	// 2 misses at a 30ms interval: the link must respawn well within 1s.
	waitFor(t, time.Second, func() bool { return dialer.dialCount("station.example", 4433) == 2 })

	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })
	a := p.connectedActors()[0]
	// The survivor must be talking to "fresh", not "silent" -- confirms
	// respawn actually happened, not a coincidental dial-count bump.
	if a.session != sessionLike(fresh) {
		t.Fatalf("connected actor is not using the respawned session")
	}
}

func TestErrorResponseIsNotGoErr(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s := newFakeSession()
	dialer.script("station.example", 4433, s)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	go func() {
		waitFor(t, time.Second, func() bool { return len(s.Sent()) > 0 })
		callID, ok := frame.FrameCallID(s.Sent()[0])
		if !ok {
			return
		}
		s.recv <- frame.CallErrorFrame(frame.NewCallErrorSpec(callID, bolt4.UnknownNextPeer, fill32(0x01)))
	}()

	resp, err := p.Call(context.Background(), fill32(0x02), "not.advertised", cbor.Null(), time.Second)
	if err != nil {
		t.Fatalf("Call returned a Go error for a wire-level ERROR response: %v", err)
	}
	if !resp.IsError {
		t.Fatalf("expected IsError response")
	}
}

// -- test helpers for reading back what an actor sent.

func subscribeFrames(frames []cbor.Value) []cbor.Value {
	var out []cbor.Value
	for _, f := range frames {
		if ft, ok := f.Get("frame_type"); ok {
			if t, _ := ft.AsText(); t == "subscribe" {
				out = append(out, f)
			}
		}
	}
	return out
}

func parseSubscribeTopic(v cbor.Value) (string, error) {
	tv, ok := v.Get("topic")
	if !ok {
		return "", errNotSubscribeFrame
	}
	b, ok := tv.AsBytes()
	if !ok {
		return "", errNotSubscribeFrame
	}
	return string(b), nil
}
