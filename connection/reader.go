package connection

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

const (
	// subscriptionQueue is how many events a subscription holds for its reader.
	subscriptionQueue = 256
	// inboundCallQueue is how many inbound CALLs wait for a serve loop.
	inboundCallQueue = 64
	// handOffQueue is how many frames the reader, or telemetry, hands to the
	// session's writer before dropping one.
	handOffQueue = 64
	// defaultSendTimeout bounds a write in progress on the control stream, and
	// the wait for the write lock of a send with no deadline of its own.
	defaultSendTimeout = 30 * time.Second
	// unroutedLogInterval is how often a count of dropped frames of one type is
	// logged.
	unroutedLogInterval = time.Minute
)

var (
	// ErrSessionEnded wraps the reason a session stopped: a GOODBYE, a
	// protocol violation, a stalled write, Close, or a failed read.
	ErrSessionEnded = errors.New("connection: session ended")
	// ErrProtocolViolation is a frame the station must not send once the
	// handshake is done, such as a second HELLO.
	ErrProtocolViolation = errors.New("connection: protocol violation")
	// ErrSendTimeout is a write on the control stream that took longer than
	// the session send timeout. A frame may be half written, so the session
	// ends.
	ErrSendTimeout = errors.New("connection: send timed out")
	// ErrNotSent is a frame that was never written, because the wait for the
	// write lock ran out first.
	ErrNotSent = errors.New("connection: frame not sent")
	// ErrCallTimeout is a Call whose timeout passed before its reply arrived.
	// It also wraps ErrNotSent when the CALL was never written.
	ErrCallTimeout = errors.New("connection: call timed out")
	// ErrConsumerOverflow ends a subscription whose queue was full when an
	// event for it arrived. The subscription still holds its share of the
	// station subscription until it is closed.
	ErrConsumerOverflow = errors.New("connection: subscription fell behind its queue and receives no more events; Close it to release the station subscription")
	// ErrRecvTimeout is a Subscription.Recv that found no event in time.
	ErrRecvTimeout = errors.New("connection: nothing arrived in time")
	// ErrSubscriptionClosed is what a closed subscription's Recv returns.
	ErrSubscriptionClosed = errors.New("connection: subscription closed")
)

// GoodbyeError is the GOODBYE a station sent to end a session.
type GoodbyeError struct {
	Reason string
	Detail string
}

func (e *GoodbyeError) Error() string {
	if e.Detail == "" {
		return "connection: the station said goodbye: " + e.Reason
	}
	return fmt.Sprintf("connection: the station said goodbye: %s (%s)", e.Reason, e.Detail)
}

// router is a session's single reader's state: calls waiting for replies,
// subscriptions, inbound CALLs waiting for a serve loop, frames handed to the
// writer, and counts of frames nothing routes.
type router struct {
	mu       sync.Mutex
	topicMu  sync.Mutex // held across a topic count change and its SUBSCRIBE or UNSUBSCRIBE write
	ended    error
	endedCh  chan struct{}
	pending  map[string]chan frame.CallResponse
	subs     map[*Subscription]struct{}
	topics   map[topicKey]int
	calls    chan frame.CallInfo
	handOffs chan cbor.Value
	unrouted map[string]*unroutedCount
	logger   *slog.Logger
}

type topicKey struct{ realm, topic string }

type unroutedCount struct {
	total    uint64
	sinceLog uint64
	lastLog  time.Time
}

// startReader starts the session's one reader of its control stream, and the
// writer that sends the frames handed to it.
func (s *Session) startReader() {
	s.rt.mu.Lock()
	s.rt.endedCh = make(chan struct{})
	s.rt.pending = map[string]chan frame.CallResponse{}
	s.rt.subs = map[*Subscription]struct{}{}
	s.rt.topics = map[topicKey]int{}
	s.rt.calls = make(chan frame.CallInfo, inboundCallQueue)
	s.rt.handOffs = make(chan cbor.Value, handOffQueue)
	s.rt.unrouted = map[string]*unroutedCount{}
	s.rt.mu.Unlock()
	go s.read()
	go s.writeHandOffs()
}

func (s *Session) read() {
	for {
		v, err := s.control.RecvFrame(time.Time{})
		if err != nil {
			if s.end(fmt.Errorf("%w: reading the control stream: %w", ErrSessionEnded, err)) {
				s.closeConnection("control stream failed")
			}
			return
		}
		if s.route(v) {
			return
		}
	}
}

// route hands one inbound frame to whoever waits for it, and reports whether
// the frame ended the session.
func (s *Session) route(v cbor.Value) (ended bool) {
	switch t := frameType(v); t {
	case "result", "error":
		s.deliverReply(v, t)
	case "event":
		s.deliverEvent(v)
	case "call":
		s.queueCall(v)
	case "goodbye":
		if s.end(fmt.Errorf("%w: %w", ErrSessionEnded, goodbyeOf(v))) {
			s.closeConnection("goodbye received")
		}
		return true
	case "hello", "connect":
		if s.end(fmt.Errorf("%w: %w: %s after the handshake", ErrSessionEnded, ErrProtocolViolation, t)) {
			s.closeConnection("protocol violation")
		}
		return true
	default:
		s.countUnrouted(t)
	}
	return false
}

func (s *Session) deliverReply(v cbor.Value, t string) {
	callID, ok := frame.FrameCallID(v)
	resp, err := frame.ParseCallResponse(v)
	if !ok || err != nil {
		s.countUnrouted(t)
		return
	}
	s.rt.mu.Lock()
	waiter, found := s.rt.pending[string(callID)]
	delete(s.rt.pending, string(callID))
	s.rt.mu.Unlock()
	if !found {
		s.countUnrouted(t)
		return
	}
	waiter <- resp
}

func (s *Session) deliverEvent(v cbor.Value) {
	evt, err := frame.ParseEvent(v)
	if err != nil {
		s.countUnrouted("event")
		return
	}
	matched := false
	var overflowed []*Subscription
	s.rt.mu.Lock()
	for sub := range s.rt.subs {
		if !sub.matches(evt) {
			continue
		}
		matched = true
		select {
		case sub.events <- evt:
		default:
			// It stops receiving but keeps its place in the topic count, so the
			// station subscription holds until its owner closes it. An
			// UNSUBSCRIBE sent from here could reach the wire after the SUBSCRIBE
			// of a subscription replacing it.
			delete(s.rt.subs, sub)
			overflowed = append(overflowed, sub)
		}
	}
	s.rt.mu.Unlock()
	for _, sub := range overflowed {
		sub.finish(ErrConsumerOverflow)
	}
	if !matched {
		s.countUnrouted("event")
	}
}

// untrackTopic takes sub off its realm and topic's count and reports whether
// it was the last subscription there. The caller holds s.rt.mu.
func (s *Session) untrackTopic(sub *Subscription) bool {
	key := sub.key()
	s.rt.topics[key]--
	if s.rt.topics[key] > 0 {
		return false
	}
	delete(s.rt.topics, key)
	return true
}

// queueCall queues a verified inbound CALL for a serve loop. A CALL that
// doesn't fit is answered with temporary_relay_failure through the writer.
func (s *Session) queueCall(v cbor.Value) {
	info, ok := verifiedCall(v)
	if !ok {
		return
	}
	select {
	case s.rt.calls <- info:
	default:
		spec := frame.NewCallErrorSpec(info.CallID, bolt4.TemporaryRelayFailure, s.self.NodeID())
		s.handOff(frame.Sign(frame.CallErrorFrame(spec), s.self))
	}
}

// handOff gives an already signed frame to the session's writer without
// waiting, so the reader and telemetry never block on a write. The frame is
// dropped when the writer is behind or the session isn't running.
func (s *Session) handOff(v cbor.Value) {
	s.rt.mu.Lock()
	queue, ended := s.rt.handOffs, s.rt.ended
	s.rt.mu.Unlock()
	if queue == nil || ended != nil {
		return
	}
	select {
	case queue <- v:
	default:
	}
}

func (s *Session) writeHandOffs() {
	for {
		select {
		case v := <-s.rt.handOffs:
			_ = s.send(v, time.Now().Add(s.sendTimeoutOrDefault()), nil)
		case <-s.rt.endedCh:
			return
		}
	}
}

// send writes v on the control stream. It waits for the write lock until
// waitUntil, or until the session ends, and then returns an error wrapping
// ErrNotSent. A write that takes longer than the session send timeout may have
// left a frame half written, so it ends the session with ErrSendTimeout.
// started, if not nil, is called once the write begins.
func (s *Session) send(v cbor.Value, waitUntil time.Time, started func()) error {
	if err := s.endedErr(); err != nil {
		return fmt.Errorf("%w: %w", err, ErrNotSent)
	}
	err := s.control.sendFrame(v, waitUntil, s.sendTimeoutOrDefault(), s.rt.endedCh, started)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errSendStopped):
		return fmt.Errorf("%w: %w", s.endedErr(), ErrNotSent)
	case errors.Is(err, errWriteLockWait):
		return fmt.Errorf("connection: send: %w", ErrNotSent)
	case isTimeout(err):
		if s.end(fmt.Errorf("%w: %w", ErrSessionEnded, ErrSendTimeout)) {
			s.closeConnection("send timed out")
		}
		return fmt.Errorf("connection: send: %w: %w", ErrSendTimeout, err)
	default:
		if s.end(fmt.Errorf("%w: writing the control stream: %w", ErrSessionEnded, err)) {
			s.closeConnection("control stream failed")
		}
		return fmt.Errorf("connection: send: %w", err)
	}
}

func (s *Session) sendTimeoutOrDefault() time.Duration {
	if s.sendTimeout > 0 {
		return s.sendTimeout
	}
	return defaultSendTimeout
}

// end stops routing with err: waiting calls fail, subscriptions end after
// what they already queued, serve loops return, sends still waiting for the
// write lock give up, Done closes, and the session is no longer offered for
// reuse. Only the first call has an effect, and it reports true.
func (s *Session) end(err error) bool {
	s.rt.mu.Lock()
	if s.rt.ended != nil {
		s.rt.mu.Unlock()
		return false
	}
	s.rt.ended = err
	pending, subs, logger := s.rt.pending, s.rt.subs, s.rt.logger
	s.rt.pending, s.rt.subs, s.rt.topics = nil, nil, nil
	if s.rt.endedCh != nil {
		close(s.rt.endedCh)
	}
	s.rt.mu.Unlock()
	for _, waiter := range pending {
		close(waiter)
	}
	for sub := range subs {
		sub.finish(err)
	}
	unregister(s)
	s.logEnd(logger, err)
	return true
}

// errClosedLocally is the reason a session Close ended.
var errClosedLocally = errors.New("closed")

// logEnd writes the one line a session's end gets when a logger is set: a
// warning when the station or the connection ended it, information when
// Close did.
func (s *Session) logEnd(logger *slog.Logger, err error) {
	if logger == nil {
		return
	}
	level := slog.LevelWarn
	if errors.Is(err, errClosedLocally) {
		level = slog.LevelInfo
	}
	logger.Log(context.Background(), level, "macula: session ended", "reason", err.Error(),
		"node", hex.EncodeToString(s.identity), "station", hex.EncodeToString(s.Station.NodeID))
}

func (s *Session) endedErr() error {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	return s.rt.ended
}

func (s *Session) closeConnection(reason string) error {
	if s.conn == nil {
		return nil
	}
	return s.conn.CloseWithError(0, reason)
}

// SetLogger sets where the session logs: the frames nothing routes, at most
// one line per frame type per minute, and its end, once, with the reason. A
// session has no logger until one is set.
func (s *Session) SetLogger(logger *slog.Logger) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	s.rt.logger = logger
}

// Unrouted returns how many inbound frames of each type nothing routed: a type
// the session doesn't handle, or a RESULT or ERROR for a call no longer waiting.
func (s *Session) Unrouted() map[string]uint64 {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	out := make(map[string]uint64, len(s.rt.unrouted))
	for t, c := range s.rt.unrouted {
		out[t] = c.total
	}
	return out
}

func (s *Session) countUnrouted(frameType string) {
	now := time.Now()
	s.rt.mu.Lock()
	if s.rt.unrouted == nil {
		s.rt.unrouted = map[string]*unroutedCount{}
	}
	c := s.rt.unrouted[frameType]
	if c == nil {
		c = &unroutedCount{}
		s.rt.unrouted[frameType] = c
	}
	c.total++
	c.sinceLog++
	logger := s.rt.logger
	var dropped uint64
	if logger != nil && (c.lastLog.IsZero() || now.Sub(c.lastLog) >= unroutedLogInterval) {
		dropped, c.sinceLog, c.lastLog = c.sinceLog, 0, now
	}
	s.rt.mu.Unlock()
	if dropped > 0 {
		logger.Warn(fmt.Sprintf("macula: dropped %d unrouted %s frame(s) in the last minute", dropped, frameType),
			"station", hex.EncodeToString(s.Station.NodeID))
	}
}

func frameType(v cbor.Value) string {
	ft, _ := v.Get("frame_type")
	t, _ := ft.AsText()
	return t
}

func goodbyeOf(v cbor.Value) *GoodbyeError {
	g := &GoodbyeError{}
	if r, ok := v.Get("reason"); ok {
		g.Reason, _ = r.AsText()
	}
	if d, ok := v.Get("detail"); ok {
		if b, ok := d.AsBytes(); ok {
			g.Detail = string(b)
		} else if t, ok := d.AsText(); ok {
			g.Detail = t
		}
	}
	return g
}

// topicMatches applies the station's topic pattern rule
// (macula_topic_pattern:matches/2): topics split on "/", a "*" segment matches
// exactly one segment, and the segment counts must be equal.
func topicMatches(pattern, topic string) bool {
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

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
