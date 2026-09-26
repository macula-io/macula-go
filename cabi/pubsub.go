package main

// #include <stdint.h>
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// publish publishes payload on topic in realm, living ttlMs (the default
// when 0).
func publish(p *pool.Pool, realm [32]byte, topic, payloadJSON string, ttlMs int64) error {
	if ttlMs < 0 {
		return invalidArgument("a negative ttl_ms")
	}
	payload, err := payloadFromJSON(payloadJSON)
	if err != nil {
		return err
	}
	publication := stationlink.Publication{Realm: realm, Topic: topic, Payload: payload}
	if ttlMs > 0 {
		ttl := uint64(ttlMs)
		publication.TTLMs = &ttl
	}
	return p.Publish(publication)
}

// subscription is a subscription with the inbox its events wait in.
type subscription struct {
	owner *livePool
	sub   *pool.Subscription
	box   *inbox
}

// subscribe subscribes to topic in realm; its events wait in the inbox until
// taken, and one that finds it full is dropped and counted.
func subscribe(lp *livePool, realm [32]byte, topic string) (*subscription, error) {
	sub, err := lp.pool.Subscribe(realm, topic)
	if err != nil {
		return nil, err
	}
	s := &subscription{owner: lp, sub: sub, box: newInbox(dropNewest)}
	lp.own(s.box)
	go func() {
		defer s.box.close()
		for event := range sub.Events() {
			s.box.push(context.Background(), inboxItem{json: eventJSON(event)})
		}
	}()
	return s, nil
}

func eventJSON(e stationlink.Event) string {
	text, _ := json.Marshal(map[string]any{
		"publisher": hex.EncodeToString(e.Publisher[:]), "realm": hex.EncodeToString(e.Realm[:]), "topic": e.Topic,
		"seq": e.Seq, "published_at": e.PublishedAt, "payload": payloadToJSON(e.Payload), "delivered_via": e.DeliveredVia,
	})
	return string(text)
}

// dropped is every event the subscription lost: those the pool dropped before
// they reached the inbox, and those the full inbox refused.
func (s *subscription) dropped() uint64 { return s.sub.Dropped() + s.box.droppedCount() }

func (s *subscription) stop() {
	_ = s.sub.Unsubscribe()
	s.box.close()
	s.owner.disown(s.box)
}

//export macula_pool_publish
func macula_pool_publish(h C.uintptr_t, realm32 *C.uint8_t, topic, payloadJSON *C.char, ttlMs C.int64_t,
	errOut **C.char) {
	lp := poolOf(h, errOut)
	if lp == nil {
		return
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return
	}
	setErr(errOut, publish(lp.pool, realm, goString(topic), goString(payloadJSON), int64(ttlMs)))
}

//export macula_pool_subscribe
func macula_pool_subscribe(h C.uintptr_t, realm32 *C.uint8_t, topic *C.char, errOut **C.char) C.uintptr_t {
	lp := poolOf(h, errOut)
	if lp == nil {
		return 0
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	s, err := subscribe(lp, realm, goString(topic))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return newHandle(s)
}

func subscriptionOf(h C.uintptr_t, errOut **C.char) *subscription {
	s, ok := valueOf[*subscription](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return nil
	}
	return s
}

//export macula_subscription_next
func macula_subscription_next(h C.uintptr_t, timeoutMs C.int64_t, token C.uintptr_t, closed *C.int32_t,
	errOut **C.char) *C.char {
	s := subscriptionOf(h, errOut)
	if s == nil {
		*closed = 0
		return nil
	}
	return takeNext(s.box, token, timeoutMs, nil, closed, errOut)
}

//export macula_subscription_dropped
func macula_subscription_dropped(h C.uintptr_t, errOut **C.char) C.uint64_t {
	s := subscriptionOf(h, errOut)
	if s == nil {
		return 0
	}
	return C.uint64_t(s.dropped())
}

//export macula_subscription_stop
func macula_subscription_stop(h C.uintptr_t) {
	if s, ok := valueOf[*subscription](h); ok {
		s.stop()
		release(h)
	}
}
