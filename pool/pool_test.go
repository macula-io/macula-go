package pool

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

var (
	errNoMoreScriptedSessions = errors.New("pool_test: dialer has no more scripted sessions for this target")
	errNotSubscribeFrame      = errors.New("pool_test: frame is not a subscribe frame")
)

// -- fakeSession: an in-memory sessionLike, driven entirely by the test, so
// respawn, replay, dedup and fall-through logic can be exercised
// deterministically without a live QUIC connection. It keeps the contract
// a connection.Session keeps: a frame pushed on recv is routed the way its
// reader routes it (RESULT and ERROR to the waiting LinkCall, EVENT to
// every subscription whose topic matches), anything tried on an ended
// session is not sent, and a write stalled past the send timeout ends the
// session.

type fakeSession struct {
	recv chan cbor.Value
	done chan struct{}

	// blockSend, when non-nil, makes Publish wait until it closes; if
	// sendTimeout passes first, the session ends with ErrSendTimeout.
	blockSend   chan struct{}
	sendTimeout time.Duration
	// endOnCall makes the session end as a LinkCall starts, before its
	// CALL is written, as when the connection drops just then.
	endOnCall bool

	mu             sync.Mutex
	sent           []cbor.Value
	ops            []string // "subscribe <topic>" and "close <topic>", in order
	pending        map[string]chan frame.CallResponse
	subs           []*fakeSubscription
	err            error
	callsAttempted int
	publishWaiting bool
}

func newFakeSession() *fakeSession {
	f := &fakeSession{
		recv:        make(chan cbor.Value, 16),
		done:        make(chan struct{}),
		sendTimeout: time.Second,
		pending:     make(map[string]chan frame.CallResponse),
	}
	go f.route()
	return f
}

func (f *fakeSession) route() {
	for {
		select {
		case <-f.done:
			return
		case v := <-f.recv:
			f.routeFrame(v)
		}
	}
}

func (f *fakeSession) routeFrame(v cbor.Value) {
	ft, _ := v.Get("frame_type")
	switch t, _ := ft.AsText(); t {
	case "result", "error":
		callID, ok := frame.FrameCallID(v)
		if !ok {
			return
		}
		resp, err := frame.ParseCallResponse(v)
		if err != nil {
			return
		}
		f.mu.Lock()
		waiter, found := f.pending[string(callID)]
		delete(f.pending, string(callID))
		f.mu.Unlock()
		if found {
			waiter <- resp
		}
	case "event":
		evt, err := frame.ParseEvent(v)
		if err != nil {
			return
		}
		f.mu.Lock()
		subs := append([]*fakeSubscription(nil), f.subs...)
		f.mu.Unlock()
		for _, sub := range subs {
			if bytes.Equal(sub.realm, evt.Realm) && fakeTopicMatches(sub.topic, evt.Topic) {
				sub.offer(evt)
			}
		}
	}
}

// fakeTopicMatches is the station's topic rule (macula_topic_pattern:matches/2),
// which a session reader applies before a subscription receives an event.
func fakeTopicMatches(pattern, topic string) bool {
	p, c := strings.Split(pattern, "/"), strings.Split(topic, "/")
	if len(p) != len(c) {
		return false
	}
	for i := range p {
		if p[i] != "*" && p[i] != c[i] {
			return false
		}
	}
	return true
}

func (f *fakeSession) LinkCall(spec frame.CallSpec, _ identity.KeyPair, timeout time.Duration) (frame.CallResponse, error) {
	if err := f.Err(); err != nil {
		return frame.CallResponse{}, fmt.Errorf("%w: %w", err, connection.ErrNotSent)
	}
	f.mu.Lock()
	f.callsAttempted++
	f.mu.Unlock()
	if f.endOnCall {
		f.end(fmt.Errorf("%w: connection lost", connection.ErrSessionEnded))
		return frame.CallResponse{}, fmt.Errorf("%w: %w", f.Err(), connection.ErrNotSent)
	}
	callID := make([]byte, 16)
	_, _ = rand.Read(callID)
	spec.CallID = callID
	reply := make(chan frame.CallResponse, 1)
	f.mu.Lock()
	f.pending[string(callID)] = reply
	f.sent = append(f.sent, frame.Call(spec))
	f.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case resp := <-reply:
		return resp, nil
	case <-timer.C:
		f.mu.Lock()
		delete(f.pending, string(callID))
		f.mu.Unlock()
		return frame.CallResponse{}, fmt.Errorf("%w waiting for a response", connection.ErrCallTimeout)
	case <-f.done:
		return frame.CallResponse{}, f.Err()
	}
}

func (f *fakeSession) Publish(spec frame.PublishSpec, _ identity.KeyPair) error {
	if err := f.Err(); err != nil {
		return fmt.Errorf("%w: %w", err, connection.ErrNotSent)
	}
	if f.blockSend != nil {
		f.mu.Lock()
		f.publishWaiting = true
		f.mu.Unlock()
		select {
		case <-f.blockSend:
		case <-time.After(f.sendTimeout):
			f.end(fmt.Errorf("%w: %w", connection.ErrSessionEnded, connection.ErrSendTimeout))
			return fmt.Errorf("fake: send: %w", connection.ErrSendTimeout)
		case <-f.done:
			return f.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, frame.Publish(spec))
	return nil
}

func (f *fakeSession) Subscribe(spec frame.SubscribeSpec, _ identity.KeyPair) (subscription, error) {
	if err := f.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", err, connection.ErrNotSent)
	}
	sub := &fakeSubscription{
		session: f,
		realm:   spec.Realm,
		topic:   spec.Topic,
		events:  make(chan frame.EventInfo, 16),
		stopped: make(chan struct{}),
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subs = append(f.subs, sub)
	f.sent = append(f.sent, frame.Subscribe(spec))
	f.ops = append(f.ops, "subscribe "+spec.Topic)
	return sub, nil
}

func (f *fakeSession) Sent() []cbor.Value {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]cbor.Value, len(f.sent))
	copy(out, f.sent)
	return out
}

func (f *fakeSession) Done() <-chan struct{} { return f.done }

func (f *fakeSession) Err() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.err
}

func (f *fakeSession) Close(string, *string, identity.KeyPair) error {
	f.end(fmt.Errorf("%w: closed", connection.ErrSessionEnded))
	return nil
}

func (f *fakeSession) RemoteAddr() string { return "fake" }

// kill simulates the connection dying out from under the link.
func (f *fakeSession) kill() {
	f.end(fmt.Errorf("%w: connection lost", connection.ErrSessionEnded))
}

func (f *fakeSession) end(err error) {
	f.mu.Lock()
	if f.err != nil {
		f.mu.Unlock()
		return
	}
	f.err = err
	subs := f.subs
	f.subs = nil
	f.mu.Unlock()
	close(f.done)
	for _, sub := range subs {
		sub.end(err)
	}
}

func (f *fakeSession) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.callsAttempted
}

func (f *fakeSession) waitingToPublish() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.publishWaiting
}

// subscriptionsTo returns the open subscriptions to topic.
func (f *fakeSession) subscriptionsTo(topic string) []*fakeSubscription {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*fakeSubscription
	for _, sub := range f.subs {
		if sub.topic == topic {
			out = append(out, sub)
		}
	}
	return out
}

// opsOn returns what was done to subscriptions to topic, in order.
func (f *fakeSession) opsOn(topic string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, op := range f.ops {
		if verb, t, _ := strings.Cut(op, " "); t == topic {
			out = append(out, verb)
		}
	}
	return out
}

type fakeSubscription struct {
	session *fakeSession
	realm   []byte
	topic   string
	events  chan frame.EventInfo
	stopped chan struct{}

	mu  sync.Mutex
	err error
}

func (s *fakeSubscription) offer(evt frame.EventInfo) {
	select {
	case s.events <- evt:
	default:
		s.end(connection.ErrConsumerOverflow)
	}
}

func (s *fakeSubscription) Recv(timeout time.Duration) (frame.EventInfo, error) {
	select {
	case evt := <-s.events:
		return evt, nil
	default:
	}
	select {
	case evt := <-s.events:
		return evt, nil
	case <-s.stopped:
		select {
		case evt := <-s.events:
			return evt, nil
		default:
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		return frame.EventInfo{}, s.err
	case <-time.After(timeout):
		return frame.EventInfo{}, connection.ErrRecvTimeout
	}
}

func (s *fakeSubscription) Close() error {
	f := s.session
	f.mu.Lock()
	f.ops = append(f.ops, "close "+s.topic)
	for i, sub := range f.subs {
		if sub == s {
			f.subs = append(f.subs[:i], f.subs[i+1:]...)
			break
		}
	}
	f.mu.Unlock()
	s.end(connection.ErrSubscriptionClosed)
	return nil
}

func (s *fakeSubscription) end(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return
	}
	s.err = err
	close(s.stopped)
}

// fakeDialer hands out a scripted sequence of sessions, one per Connect
// attempt, keyed by host:port -- lets a test control exactly which
// (possibly multiple, across respawns) fake session a given link dials
// into, and count how many times each target was dialed.
type fakeDialer struct {
	mu      sync.Mutex
	scripts map[string][]*fakeSession // host:port -> sessions to hand out in order
	dials   map[string]int
	nodeIDs map[string][]byte // host:port -> node id dial() reports; unset -> "fake-node-id" for every target
}

func newFakeDialer() *fakeDialer {
	return &fakeDialer{scripts: make(map[string][]*fakeSession), dials: make(map[string]int), nodeIDs: make(map[string][]byte)}
}

func (d *fakeDialer) script(host string, port uint16, sessions ...*fakeSession) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.scripts[linkKey(host, port)] = sessions
}

// scriptNodeID overrides the node id dial() reports for host:port --
// without this, every target reports the same constant "fake-node-id",
// which is fine for tests that don't care about peer identity but
// collapses any test asserting dedup-by-node-id across multiple
// targets (they'd all look like the same peer). Must be called before
// Connect/addLink dials that target.
func (d *fakeDialer) scriptNodeID(host string, port uint16, nodeID []byte) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.nodeIDs[linkKey(host, port)] = nodeID
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
	nodeID := d.nodeIDs[key]
	if nodeID == nil {
		nodeID = []byte("fake-node-id")
	}
	return dialResult{session: sessions[n], nodeID: nodeID, remote: "fake"}, nil
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

	k1 := newDedupKey("topic", realmA, pub, 1, "topic")
	if d.CheckAndMark(k1, now) {
		t.Fatalf("first sighting reported as duplicate")
	}

	k2 := newDedupKey("topic", realmACopy, pub, 1, "topic")
	if !d.CheckAndMark(k2, now) {
		t.Fatalf("same content from a different byte-slice allocation did not collide")
	}

	k3 := newDedupKey("other-topic", realmA, pub, 1, "other-topic")
	if d.CheckAndMark(k3, now) {
		t.Fatalf("different topic incorrectly collided -- this is the exact bug shape (Realm,Publisher,Seq) without Topic had")
	}

	k4 := newDedupKey("topic", realmA, pub, 2, "topic")
	if d.CheckAndMark(k4, now) {
		t.Fatalf("different seq incorrectly collided")
	}

	k5 := newDedupKey("*", realmA, pub, 1, "topic")
	if d.CheckAndMark(k5, now) {
		t.Fatalf("the same event received by another subscribed pattern incorrectly collided")
	}
}

func TestDedupTableSweepRemovesOnlyStaleEntries(t *testing.T) {
	d := newDedupTable()
	base := time.Now()

	old := newDedupKey("t", []byte("r"), []byte("p"), 1, "t")
	fresh := newDedupKey("t", []byte("r"), []byte("p"), 2, "t")

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

// -- Pool integration, driven by fakeDialer/fakeSession: respawn, replay, dedup, fall-through.

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

func TestAWildcardSubscriptionThroughThePoolReceivesMatchingEvents(t *testing.T) {
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

	realm := fill32(0x51)
	var mu sync.Mutex
	received := map[string][]string{}
	recordAs := func(name string) EventHandler {
		return func(_ []byte, topic string, _ cbor.Value) {
			mu.Lock()
			defer mu.Unlock()
			received[name] = append(received[name], topic)
		}
	}
	p.Subscribe(realm, "sensors/*", recordAs("wildcard"))
	p.Subscribe(realm, "sensors/kitchen", recordAs("concrete"))
	waitFor(t, time.Second, func() bool { return len(subscribeFrames(s.Sent())) == 2 })

	s.recv <- rawEventFrame(t, realm, fill32(0x52), "sensors/kitchen", 1, cbor.Text("warm"))
	s.recv <- rawEventFrame(t, realm, fill32(0x52), "sensors/hall", 2, cbor.Text("cold"))

	want := func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received["wildcard"]) == 2 && len(received["concrete"]) == 1
	}
	deadline := time.Now().Add(time.Second)
	for !want() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond) // a duplicate delivery would have landed by now
	mu.Lock()
	defer mu.Unlock()
	if len(received["wildcard"]) != 2 || len(received["concrete"]) != 1 {
		t.Fatalf("deliveries = %v, want sensors/* to receive kitchen and hall once each and sensors/kitchen to receive kitchen once", received)
	}
}

func TestAnOverflowedSubscriptionIsReplacedBeforeItIsClosed(t *testing.T) {
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

	realm := fill32(0x61)
	delivered := make(chan string, 4)
	p.Subscribe(realm, "flood", func(_ []byte, _ string, payload cbor.Value) {
		txt, _ := payload.AsText()
		delivered <- txt
	})
	waitFor(t, time.Second, func() bool { return len(s.subscriptionsTo("flood")) == 1 })

	s.subscriptionsTo("flood")[0].end(connection.ErrConsumerOverflow)

	waitFor(t, time.Second, func() bool { return len(s.opsOn("flood")) == 3 })
	if ops := s.opsOn("flood"); ops[1] != "subscribe" || ops[2] != "close" {
		t.Fatalf("operations on the flood subscriptions = %v, want subscribe, subscribe, close: the replacement subscribes before the overflowed one closes", ops)
	}

	s.recv <- rawEventFrame(t, realm, fill32(0x62), "flood", 1, cbor.Text("after"))
	select {
	case got := <-delivered:
		if got != "after" {
			t.Fatalf("delivered %q, want %q", got, "after")
		}
	case <-time.After(time.Second):
		t.Fatal("the replacement subscription delivered nothing")
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

// A link whose session ended just as the call started never sent the
// CALL, so Call moves on to the next link.
func TestCallFallsThroughToNextConnectedLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	dead := newFakeSession()
	dead.endOnCall = true
	live := newFakeSession()
	dialer.script("dead.example", 4433, dead)
	dialer.script("live.example", 4433, live)
	autoReplyWithHostname(live, "live.example")

	p, err := Connect(context.Background(), []Seed{{Host: "dead.example", Port: 4433}, {Host: "live.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 2 })

	// Which link a call tries first follows map order, so call until one
	// call has tried the dead link; every call must still be answered.
	deadline := time.Now().Add(5 * time.Second)
	for dead.callCount() == 0 && time.Now().Before(deadline) {
		resp, err := p.Call(context.Background(), fill32(0xEE), "some.procedure", cbor.Null(), time.Second)
		if err != nil {
			t.Fatalf("Call: %v", err)
		}
		if txt, _ := resp.Payload.AsText(); txt != "live.example" {
			t.Fatalf("Call payload = %v, want %q", resp.Payload, "live.example")
		}
	}
	if dead.callCount() == 0 {
		t.Fatal("no call ever tried the dead link first")
	}
}

func TestAPoolCallThatTimedOutAfterItsWriteStartedIsNotTriedOnAnotherLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	silent := newFakeSession() // takes every CALL and never answers
	live := newFakeSession()
	dialer.script("silent.example", 4433, silent)
	dialer.script("live.example", 4433, live)
	autoReplyWithHostname(live, "live.example")

	p, err := Connect(context.Background(), []Seed{{Host: "silent.example", Port: 4433}, {Host: "live.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 2 })

	// Which link a call tries first follows map order, so call until one
	// call has tried the silent link first.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		silentCalls, liveCalls := silent.callCount(), live.callCount()
		resp, err := p.Call(context.Background(), fill32(0xEE), "some.procedure", cbor.Null(), 50*time.Millisecond)
		if silent.callCount() == silentCalls {
			if err != nil {
				t.Fatalf("Call answered by the live link: %v", err)
			}
			continue
		}
		if !errors.Is(err, connection.ErrCallTimeout) || errors.Is(err, connection.ErrNotSent) {
			t.Fatalf("Call through the silent link = (%v, %v), want ErrCallTimeout without ErrNotSent", resp.Payload, err)
		}
		if live.callCount() != liveCalls {
			t.Fatal("a call that may have reached its provider was sent again on another link")
		}
		return
	}
	t.Fatal("no call ever tried the silent link first")
}

// A link whose writes stall past its session's send timeout ends and is
// respawned, and while a Publish waits on it the rest of the pool keeps
// working.
func TestStalledWriterRespawnsInsteadOfWedging(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	stalled := newFakeSession()
	stalled.blockSend = make(chan struct{}) // never closed
	stalled.sendTimeout = 300 * time.Millisecond
	fresh := newFakeSession()
	dialer.script("station.example", 4433, stalled, fresh)

	p, err := Connect(context.Background(), []Seed{{Host: "station.example", Port: 4433}}, testOpts(id, dialer.dial))
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })

	realm := fill32(0x77)
	published := make(chan error, 1)
	go func() { published <- p.Publish(realm, "stalls", cbor.Uint64(1)) }()
	waitFor(t, time.Second, stalled.waitingToPublish)

	returned := make(chan struct{})
	go func() {
		p.Subscribe(realm, "still.works", func([]byte, string, cbor.Value) {})
		_ = p.Status()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Subscribe and Status waited on a Publish stalled on one link")
	}

	if err := <-published; !errors.Is(err, connection.ErrSendTimeout) {
		t.Fatalf("Publish on the stalled link = %v, want ErrSendTimeout", err)
	}
	waitFor(t, 5*time.Second, func() bool { return dialer.dialCount("station.example", 4433) == 2 })
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 1 })
	if ls := p.connectedSessions()[0]; ls.session != sessionLike(fresh) {
		t.Fatalf("connected link is not using the respawned session")
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

func TestPublishRejectsBadPayloadWithoutTouchingAnyLink(t *testing.T) {
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

func TestCallRejectsBadPayloadWithoutTouchingAnyLink(t *testing.T) {
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
	ls := p.connectedSessions()[0]
	// The survivor must be talking to "fresh", not "silent" -- confirms
	// respawn actually happened, not a coincidental dial-count bump.
	if ls.session != sessionLike(fresh) {
		t.Fatalf("connected link is not using the respawned session")
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

// -- test helpers for reading back what a link sent.

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
