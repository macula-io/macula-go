package pool

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// recvPollInterval bounds one Subscription.Recv wait. Not a wire timeout: a
// forwarder simply waits again.
const recvPollInterval = 2 * time.Second

// eventQueueCap bounds the channel every link's subscriptions forward events
// into for the pool's dedup and fanout.
const eventQueueCap = 256

// Liveness probe defaults, matching macula_station_link.erl's own
// ?LIVENESS_INTERVAL_MS/?LIVENESS_MAX_MISSES exactly -- see probe's own
// doc for why this exists at all.
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

// inboundEvent is one EVENT a link's subscription received, forwarded to
// the pool coordinator, which owns dedup and local subscriber fanout.
// pattern is the subscribed topic that received it, which a "*" segment
// can make differ from the event's own topic.
type inboundEvent struct {
	linkKey   string
	pattern   string
	realm     []byte
	publisher []byte
	seq       uint64
	topic     string
	payload   cbor.Value
}

// linkSession is one session a link holds, from its dial until it ends.
// The session itself carries any number of concurrent calls, publishes and
// subscriptions (its single reader routes replies and events), so this
// adds only what a pool link needs on top: one subscription per tracked
// realm and topic, forwarded into the pool, and an application-level
// liveness probe.
type linkSession struct {
	linkKey string
	session sessionLike
	id      identity.KeyPair

	livenessInterval  time.Duration
	livenessMaxMisses int

	events chan<- inboundEvent
	done   chan struct{} // closed exactly once, when run returns
	failed chan error    // buffered 1: why this link can no longer carry its work

	mu     sync.Mutex
	topics map[topicKey]struct{} // realm and topic pairs subscribed on this session
}

func newLinkSession(linkKey string, session sessionLike, id identity.KeyPair, events chan<- inboundEvent, livenessInterval time.Duration, livenessMaxMisses int) *linkSession {
	return &linkSession{
		linkKey:           linkKey,
		session:           session,
		id:                id,
		livenessInterval:  livenessInterval,
		livenessMaxMisses: livenessMaxMisses,
		events:            events,
		done:              make(chan struct{}),
		failed:            make(chan error, 1),
		topics:            make(map[topicKey]struct{}),
	}
}

// run blocks until ctx is cancelled, the session ends, the liveness probe
// misses livenessMaxMisses in a row, or a subscription cannot be carried.
// It always returns a non-nil reason and closes the session on its way
// out. The caller (link.go) owns respawn, backoff and replay; this
// method's only job is one session for as long as it lives.
func (ls *linkSession) run(ctx context.Context) error {
	defer close(ls.done)
	defer func() { _ = ls.session.Close("pool: link closing", nil, ls.id) }() // best-effort on every exit path, including an already-ended session

	probeCtx, stopProbe := context.WithCancel(ctx)
	defer stopProbe()
	go ls.probe(probeCtx)

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ls.session.Done():
		return fmt.Errorf("pool: link %s: %w", ls.linkKey, ls.session.Err())
	case err := <-ls.failed:
		return err
	}
}

// fail ends run with err, unless it is already ending for another reason.
func (ls *linkSession) fail(err error) {
	select {
	case ls.failed <- err:
	default:
	}
}

// subscribe subscribes this session to key's realm and topic, once, and
// forwards what that subscription receives into the pool. A link that
// cannot subscribe is failed, so its respawn replays every tracked topic.
func (ls *linkSession) subscribe(key topicKey) {
	ls.mu.Lock()
	_, already := ls.topics[key]
	ls.topics[key] = struct{}{}
	ls.mu.Unlock()
	if already {
		return
	}
	sub, err := ls.session.Subscribe(ls.subscribeSpec(key), ls.id)
	if err != nil {
		ls.fail(fmt.Errorf("pool: link %s: subscribe to %q: %w", ls.linkKey, key.topic, err))
		return
	}
	go ls.forward(key, sub)
}

func (ls *linkSession) subscribeSpec(key topicKey) frame.SubscribeSpec {
	return frame.NewSubscribeSpec(key.topic, []byte(key.realm), ls.id.NodeID())
}

// forward hands every event sub receives to the pool, until the
// subscription ends with its session. A subscription that fell behind its
// queue is replaced first and closed after, so the session stays
// subscribed at the station throughout.
func (ls *linkSession) forward(key topicKey, sub subscription) {
	for {
		evt, err := sub.Recv(recvPollInterval)
		switch {
		case err == nil:
			select {
			case ls.events <- inboundEvent{
				linkKey: ls.linkKey, pattern: key.topic, realm: evt.Realm, publisher: evt.Publisher,
				seq: evt.Seq, topic: evt.Topic, payload: evt.Payload,
			}:
			case <-ls.done:
				return
			}
		case errors.Is(err, connection.ErrRecvTimeout):
		case errors.Is(err, connection.ErrConsumerOverflow):
			fresh, err := ls.session.Subscribe(ls.subscribeSpec(key), ls.id)
			_ = sub.Close()
			if err != nil {
				ls.fail(fmt.Errorf("pool: link %s: replace the overflowed subscription to %q: %w", ls.linkKey, key.topic, err))
				return
			}
			sub = fresh
		default:
			return
		}
	}
}

// probe is macula_station_link.erl's own liveness probe, ported: every
// livenessInterval, a tiny CALL to a well-known procedure no station
// handler ever answers (the station itself replies unknown_next_peer --
// any reply at all, error included, is what proves the peer's application
// layer is still alive). livenessMaxMisses probes in a row without a reply
// fail the link.
//
// Why this exists on top of transport.Dial's own keepalive: quic-go's
// keepalive proves the TRANSPORT is alive -- it says nothing about whether
// the peer's application process is still the one that answered
// CONNECT/HELLO. A container restart on the station side can leave the
// OS-level QUIC state acking keepalive PINGs for many minutes
// (macula_station_link.erl's own doc: observed 14+ minutes) while every
// application-level fact about this connection is gone -- exactly the
// window a pool whose entire purpose is "notice a dead link and respawn
// it" must not have.
func (ls *linkSession) probe(ctx context.Context) {
	ticker := time.NewTicker(ls.livenessInterval)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		deadlineMs := time.Now().Add(ls.livenessInterval).UnixMilli()
		spec := frame.NewCallSpec(nil, livenessProcedure, dhtRealm, cbor.Null(), deadlineMs, ls.id.NodeID())
		_, err := ls.session.LinkCall(spec, ls.id, ls.livenessInterval)
		switch {
		case err == nil:
			misses = 0
		case errors.Is(err, connection.ErrSessionEnded):
			return
		default:
			misses++
			if misses >= ls.livenessMaxMisses {
				ls.fail(fmt.Errorf("pool: link %s: liveness probe missed %d times: %w", ls.linkKey, misses, err))
				return
			}
		}
	}
}
