package connection

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// Subscription is one subscriber's events for a realm and topic on a session,
// in the order the station delivered them, in a queue of its own. A topic with
// a "*" segment matches any one segment there, as the station matches it.
// Several subscriptions can share a session and a topic; each gets its own
// copy of every event it matches.
//
// A subscription that falls behind its queue ends with ErrConsumerOverflow but
// keeps the station subscribed until it is closed, so a subscriber that wants
// the events again subscribes a replacement first and then closes it.
type Subscription struct {
	session *Session
	spec    frame.SubscribeSpec
	id      identity.KeyPair
	events  chan frame.EventInfo
	stopped chan struct{}
	tracked bool // counted in the session's topics; guarded by the session's rt.mu
	mu      sync.Mutex
	err     error
	closed  sync.Once
}

// Subscribe starts a subscription to spec's realm and topic. The station is
// sent a SUBSCRIBE only for the session's first subscription to that realm and
// topic.
func (s *Session) Subscribe(spec frame.SubscribeSpec, id identity.KeyPair) (*Subscription, error) {
	sub := &Subscription{
		session: s,
		spec:    spec,
		id:      id,
		events:  make(chan frame.EventInfo, subscriptionQueue),
		stopped: make(chan struct{}),
	}
	s.rt.topicMu.Lock()
	defer s.rt.topicMu.Unlock()
	s.rt.mu.Lock()
	if s.rt.ended != nil {
		err := s.rt.ended
		s.rt.mu.Unlock()
		return nil, err
	}
	s.rt.subs[sub] = struct{}{}
	sub.tracked = true
	s.rt.topics[sub.key()]++
	first := s.rt.topics[sub.key()] == 1
	s.rt.mu.Unlock()
	if !first {
		return sub, nil
	}
	if err := s.send(frame.Sign(frame.Subscribe(spec), id), time.Now().Add(s.sendTimeoutOrDefault()), nil); err != nil {
		s.untrack(sub)
		sub.finish(err)
		return nil, fmt.Errorf("connection: subscribe: %w", err)
	}
	return sub, nil
}

// Recv returns the next event, waiting at most timeout. It returns
// ErrRecvTimeout when none arrives in time. Once the subscription has ended it
// still returns the events it had queued, then the reason it ended:
// ErrConsumerOverflow, ErrSubscriptionClosed, or the session's end. After
// ErrConsumerOverflow, Close the subscription to release the station
// subscription.
func (sub *Subscription) Recv(timeout time.Duration) (frame.EventInfo, error) {
	select {
	case evt := <-sub.events:
		return evt, nil
	default:
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case evt := <-sub.events:
		return evt, nil
	case <-sub.stopped:
		select {
		case evt := <-sub.events:
			return evt, nil
		default:
			return frame.EventInfo{}, sub.stopErr()
		}
	case <-timer.C:
		return frame.EventInfo{}, ErrRecvTimeout
	}
}

// Close ends the subscription, including one that ended with
// ErrConsumerOverflow. When it was the session's last subscription to its
// realm and topic, the station is sent an UNSUBSCRIBE. Closing again does
// nothing.
func (sub *Subscription) Close() error {
	var err error
	sub.closed.Do(func() {
		s := sub.session
		s.rt.topicMu.Lock()
		defer s.rt.topicMu.Unlock()
		last := s.untrack(sub)
		sub.finish(ErrSubscriptionClosed)
		if last {
			err = s.send(sub.unsubscribeFrame(), time.Now().Add(s.sendTimeoutOrDefault()), nil)
		}
	})
	return err
}

// untrack stops routing to sub and takes it off its realm and topic's count.
// It reports whether sub was the last subscription there on a session still
// running. The caller holds s.rt.topicMu.
func (s *Session) untrack(sub *Subscription) (last bool) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	delete(s.rt.subs, sub)
	if sub.tracked && s.rt.ended == nil {
		last = s.untrackTopic(sub)
	}
	sub.tracked = false
	return last
}

func (sub *Subscription) key() topicKey {
	return topicKey{realm: string(sub.spec.Realm), topic: sub.spec.Topic}
}

func (sub *Subscription) matches(evt frame.EventInfo) bool {
	return bytes.Equal(evt.Realm, sub.spec.Realm) && topicMatches(sub.spec.Topic, evt.Topic)
}

func (sub *Subscription) unsubscribeFrame() cbor.Value {
	spec := frame.NewUnsubscribeSpec(sub.spec.Topic, sub.spec.Realm, sub.spec.Subscriber)
	return frame.Sign(frame.Unsubscribe(spec), sub.id)
}

func (sub *Subscription) finish(err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.err != nil {
		return
	}
	sub.err = err
	close(sub.stopped)
}

func (sub *Subscription) stopErr() error {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.err
}
