package pool

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// recvPollInterval bounds how long one RecvAny wait blocks between
// checking ctx — matches connection.subscriberPollInterval's own
// reasoning exactly (not a wire timeout, just how promptly a cancelled
// ctx is noticed when nothing is arriving).
const recvPollInterval = 2 * time.Second

// outboxCap bounds the actor's outbound queue -- once exceeded, this
// link is treated as fatal (see run's own doc for why: a stalled peer
// withholding flow-control credit forever is indistinguishable from a
// dead one, and this link should respawn rather than accumulate frames
// without bound).
const outboxCap = 128

// eventQueueCap bounds each actor's forwarding channel to the pool
// coordinator. Sized the same way as outboxCap, same reasoning.
const eventQueueCap = 256

// Liveness probe defaults, matching macula_station_link.erl's own
// ?LIVENESS_INTERVAL_MS/?LIVENESS_MAX_MISSES exactly -- see run's own
// doc for why this exists at all (a transport-level keepalive, added to
// this port's own transport.Dial change, makes the zombie window this
// closes WORSE, not better, if nothing else covers it).
const (
	DefaultLivenessInterval  = 30 * time.Second
	DefaultLivenessMaxMisses = 2
)

// livenessProcedure/dhtRealm match macula_station_link.erl's own
// ?LIVENESS_PROCEDURE/?DHT_REALM exactly -- a tiny CALL with no handler
// expected on either side; the station replies unknown_next_peer, and
// that reply (not its content) is the only thing that matters.
const livenessProcedure = "_macula.ping"

var dhtRealm = make([]byte, 32)

var (
	errLinkDown    = errors.New("pool: link is down")
	errCallTimeout = errors.New("pool: call timed out")
)

// inboundEvent is a parsed EVENT frame plus which link it arrived on —
// forwarded to the pool coordinator, which owns dedup and local
// subscriber fanout. The actor deliberately does no topic filtering of
// its own before forwarding — mirrors macula_station_link.erl, which
// hands every EVENT to the pool without deciding who locally cares.
type inboundEvent struct {
	linkKey   string
	realm     []byte
	publisher []byte
	seq       uint64
	topic     string
	payload   cbor.Value
}

// callResult is what a callCmd's reply channel carries — either a
// parsed RESULT/ERROR response, or err set (actor died, or the caller's
// own timeout fired first).
type callResult struct {
	resp frame.CallResponse
	err  error
}

// actorCmd is the tagged-union of operations sent into an actor's
// inbox. All mutation of actor-owned state (pending calls, outbox)
// happens on the actor's own goroutine, driven by these — never from
// another goroutine reaching in directly.
type actorCmd interface{ isActorCmd() }

// subscribeCmd is the only wire-subscription command this package
// sends -- there is no unsubscribeCmd. Matches macula_client.erl's own
// documented choice (see Unsubscribe's doc in subscribe.go): the
// wire-level SUBSCRIBE persists for the link's lifetime even after the
// last local subscriber drops.
type subscribeCmd struct{ spec frame.SubscribeSpec }
type publishCmd struct {
	spec   frame.PublishSpec
	result chan error // buffered 1
}
type callCmd struct {
	spec  frame.CallSpec
	reply chan callResult // buffered 1
}
type cancelCallCmd struct{ callID string }

// pendingCountCmd is a debug/test introspection command — reading
// a.pending from any goroutine but the actor's own would race with
// handleCmd's map mutations (exactly the race a bare field read would
// hit; this routes the read through the same single-writer channel
// discipline as every other command instead).
type pendingCountCmd struct{ reply chan int }

func (subscribeCmd) isActorCmd()    {}
func (publishCmd) isActorCmd()      {}
func (callCmd) isActorCmd()         {}
func (cancelCallCmd) isActorCmd()   {}
func (pendingCountCmd) isActorCmd() {}

// actor is the sole owner of one link's session I/O — reads AND writes.
// Two supporting goroutines (reader, writer) exist only to keep the main
// dispatch loop from ever blocking on the wire: a stalled peer (quic-go's
// Write parks on flow-control credit; Erlang's own link send is an async
// gen_statem cast and never blocks this way) must not freeze RESULT
// matching for every other in-flight call on this link, and an inbound
// CALL's handler must run on its OWN goroutine (spawned per call,
// mirroring macula_station_link.erl's own per-request spawn), never
// inline on the dispatch loop — a handler that itself calls back into
// the pool against this same link would otherwise self-deadlock (the
// only goroutine that could ever drain that request is the one blocked
// running the handler).
//
// Outbound frames go through an in-memory FIFO (outbox), drained into
// the writer's channel via an "optional send" case in run's own select
// loop — NOT via a helper that blocks on a full writeQueue from inside
// the dispatch loop itself. That earlier shape was reviewed and found
// broken: the actor's own done channel only closes when run returns, so
// a blocking send from WITHIN run's own goroutine could never be rescued
// by watching done — run cannot reach the code that closes done while
// it is stuck blocked earlier in the same call stack. A stalled peer
// would fill the queue and then wedge the whole actor — no further
// commands processed, no session.Done()/writeErr ever observed — forever,
// not just until the connection was noticed dead. The fix is the
// standard Go pattern for an optional outgoing send: a nil channel value
// in a select case is simply never ready, so the case is only "armed"
// (assigned the real channel) when outbox has something to send, and
// every OTHER case (ctx, session.Done, readErr, writeErr, inbox, frames)
// stays live on every iteration regardless. outboxCap still bounds
// memory; exceeding it is now treated as this link being fatally
// unhealthy (forces a respawn) rather than a wedge.
//
// run also owns an application-level liveness probe (tickLiveness) —
// see its own doc for why a transport-level keepalive alone is
// insuficient and can make the failure mode worse.
type actor struct {
	linkKey string
	session sessionLike
	id      identity.KeyPair

	livenessInterval  time.Duration
	livenessMaxMisses int

	inbox      chan actorCmd
	frames     chan cbor.Value
	readErr    chan error
	writeQueue chan cbor.Value
	writeErr   chan error
	events     chan<- inboundEvent

	done chan struct{} // closed exactly once, when run() returns

	outbox  []cbor.Value
	pending map[string]chan callResult

	pingCallID string
	pingMisses int
}

func newActor(linkKey string, session sessionLike, id identity.KeyPair, events chan<- inboundEvent, livenessInterval time.Duration, livenessMaxMisses int) *actor {
	return &actor{
		linkKey:           linkKey,
		session:           session,
		id:                id,
		livenessInterval:  livenessInterval,
		livenessMaxMisses: livenessMaxMisses,
		inbox:             make(chan actorCmd),
		frames:            make(chan cbor.Value),
		readErr:           make(chan error, 1),
		writeQueue:        make(chan cbor.Value, outboxCap),
		writeErr:          make(chan error, 1),
		events:            events,
		done:              make(chan struct{}),
		pending:           make(map[string]chan callResult),
	}
}

// send delivers cmd to the actor's inbox, but never blocks forever on a
// dead or shutting-down actor. Only safe to call from a goroutine OTHER
// than this actor's own run() -- see run's own doc on why a blocking
// send from inside run's goroutine can never be rescued by done.
func (a *actor) send(ctx context.Context, cmd actorCmd) error {
	select {
	case a.inbox <- cmd:
		return nil
	case <-a.done:
		return errLinkDown
	case <-ctx.Done():
		return ctx.Err()
	}
}

// run is the actor's main loop — blocks until ctx is cancelled, the
// session dies (Done(), a read error, a write error), or the outbox
// overflows (writer stalled past outboxCap frames) or the liveness
// probe misses livenessMaxMisses in a row. Always returns a non-nil
// reason. The caller (link.go) owns respawn/backoff/replay; this
// method's only job is one session's I/O for as long as it lives.
func (a *actor) run(ctx context.Context) error {
	defer close(a.done)
	defer a.drainPending(errLinkDown)
	defer func() { _ = a.session.Close("pool: link closing", nil, a.id) }() // best-effort on every exit path, including an already-dead session

	readerCtx, stopReader := context.WithCancel(ctx)
	defer stopReader()
	go a.readLoop(readerCtx)

	writerCtx, stopWriter := context.WithCancel(ctx)
	defer stopWriter()
	go a.writeLoop(writerCtx)

	liveness := time.NewTicker(a.livenessInterval)
	defer liveness.Stop()

	for {
		var sendCh chan cbor.Value
		var sendVal cbor.Value
		if len(a.outbox) > 0 {
			sendCh = a.writeQueue
			sendVal = a.outbox[0]
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.session.Done():
			return errLinkDown
		case err := <-a.readErr:
			return fmt.Errorf("pool: link %s: read: %w", a.linkKey, err)
		case err := <-a.writeErr:
			return fmt.Errorf("pool: link %s: write: %w", a.linkKey, err)
		case cmd := <-a.inbox:
			a.handleCmd(cmd)
		case v := <-a.frames:
			a.dispatch(ctx, v)
		case <-liveness.C:
			if err := a.tickLiveness(); err != nil {
				return err
			}
		case sendCh <- sendVal:
			a.outbox = a.outbox[1:]
		}

		if len(a.outbox) > outboxCap {
			return fmt.Errorf("pool: link %s: outbox exceeded %d frames -- peer is not draining", a.linkKey, outboxCap)
		}
	}
}

func (a *actor) drainPending(reason error) {
	for id, ch := range a.pending {
		ch <- callResult{err: reason}
		delete(a.pending, id)
	}
}

func (a *actor) handleCmd(cmd actorCmd) {
	switch c := cmd.(type) {
	case subscribeCmd:
		a.enqueue(frame.Sign(frame.Subscribe(c.spec), a.id))
	case publishCmd:
		unsigned := frame.Publish(c.spec)
		withPublisherSig := frame.SignPublisher(unsigned, a.id)
		a.enqueue(frame.Sign(withPublisherSig, a.id))
		if c.result != nil {
			c.result <- nil // enqueued -- PUBLISH has no wire ack to wait for, matches Session.Publish
		}
	case callCmd:
		a.pending[string(c.spec.CallID)] = c.reply
		a.enqueue(frame.Sign(frame.Call(c.spec), a.id))
	case cancelCallCmd:
		delete(a.pending, c.callID) // no-op if already delivered/removed
	case pendingCountCmd:
		c.reply <- len(a.pending)
	}
}

// pendingCount reads the number of in-flight calls this actor is
// currently tracking, via the actor's own goroutine — debug/test use.
func (a *actor) pendingCount(ctx context.Context) (int, error) {
	reply := make(chan int, 1)
	if err := a.send(ctx, pendingCountCmd{reply: reply}); err != nil {
		return 0, err
	}
	select {
	case n := <-reply:
		return n, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-a.done:
		return 0, errLinkDown
	}
}

// enqueue appends v to the outbox -- run's own select loop drains it
// into the writer without ever blocking here. Only safe to call from
// run's own goroutine (handleCmd/tickLiveness, both called from run).
func (a *actor) enqueue(v cbor.Value) {
	a.outbox = append(a.outbox, v)
}

// tickLiveness is macula_station_link.erl's own liveness probe, ported:
// send a tiny CALL to a well-known procedure no station handler ever
// answers (the station itself replies unknown_next_peer -- any reply at
// all, error included, is what proves the peer's application layer is
// still alive); if the previous tick's probe never got ANY reply,
// that's one miss, and livenessMaxMisses consecutive misses closes this
// link.
//
// Why this exists on top of transport.Dial's own keepalive: quic-go's
// keepalive (this port's own change) proves the TRANSPORT is alive --
// it says nothing about whether the peer's application process is still
// the one that answered CONNECT/HELLO. A container restart on the
// station side can leave the OS-level QUIC state acking keepalive PINGs
// for many minutes (macula_station_link.erl's own doc: observed 14+
// minutes) while every application-level fact about this connection is
// gone -- exactly the window a pool whose entire purpose is "notice a
// dead link and respawn it" must not have.
func (a *actor) tickLiveness() error {
	if a.pingCallID != "" {
		a.pingMisses++
		if a.pingMisses >= a.livenessMaxMisses {
			return fmt.Errorf("pool: link %s: liveness probe missed %d times", a.linkKey, a.pingMisses)
		}
	}
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		return nil // don't fail the link over a rand hiccup -- try again next tick
	}
	a.pingCallID = string(callID)
	deadlineMs := time.Now().Add(a.livenessInterval).UnixMilli()
	spec := frame.NewCallSpec(callID, livenessProcedure, dhtRealm, cbor.Null(), deadlineMs, a.id.NodeID())
	a.enqueue(frame.Sign(frame.Call(spec), a.id))
	return nil
}

func (a *actor) dispatch(ctx context.Context, v cbor.Value) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return
	}
	t, _ := ft.AsText()
	switch t {
	case "event":
		a.dispatchEvent(ctx, v)
	case "result", "error":
		a.dispatchCallResponse(v)
	default:
		// Not ours -- e.g. a stray "call" (serving is out of scope for
		// v1, see the type's own doc) -- ignore, matching
		// RunSubscriber/ServeOneCall's own unknown-frame-type handling.
	}
}

func (a *actor) dispatchEvent(ctx context.Context, v cbor.Value) {
	evt, err := frame.ParseEvent(v)
	if err != nil {
		return // a malformed "event"-typed frame -- ignore, matches RunSubscriber
	}
	select {
	case a.events <- inboundEvent{
		linkKey: a.linkKey, realm: evt.Realm, publisher: evt.Publisher,
		seq: evt.Seq, topic: evt.Topic, payload: evt.Payload,
	}:
	case <-ctx.Done():
	}
}

func (a *actor) dispatchCallResponse(v cbor.Value) {
	callID, ok := frame.FrameCallID(v)
	if !ok {
		return
	}
	key := string(callID)

	if key == a.pingCallID {
		// Any reply -- RESULT or ERROR alike, the station is documented
		// to answer unknown_next_peer since nothing ever advertises this
		// procedure -- proves the peer's application layer is alive.
		a.pingCallID = ""
		a.pingMisses = 0
		return
	}

	resp, err := frame.ParseCallResponse(v)
	if err != nil {
		return
	}
	ch, found := a.pending[key]
	if !found {
		return // no longer waiting -- already timed out/cancelled, or a duplicate
	}
	delete(a.pending, key)
	ch <- callResult{resp: resp} // buffered 1 -- never blocks
}

func (a *actor) readLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		v, err := a.session.RecvAny(time.Now().Add(recvPollInterval))
		if err != nil {
			if isRecvTimeout(err) {
				continue
			}
			select {
			case a.readErr <- err:
			case <-ctx.Done():
			}
			return
		}
		select {
		case a.frames <- v:
		case <-ctx.Done():
			return
		}
	}
}

func (a *actor) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-a.writeQueue:
			if err := a.session.SendAny(v); err != nil {
				select {
				case a.writeErr <- err:
				case <-ctx.Done():
				}
				return
			}
		}
	}
}

// isRecvTimeout mirrors connection's own unexported isRecvTimeout —
// small enough (a net.Error timeout check) to duplicate rather than
// export from a package this one otherwise only calls into.
func isRecvTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
