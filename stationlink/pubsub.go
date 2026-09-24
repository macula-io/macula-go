package stationlink

import (
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// PubSub, as macula 12's link does it. A PUBLISH carries a publication signed
// with the link's identity key; SUBSCRIBE and UNSUBSCRIBE are control frames
// naming the realm, the topic (as bytes) and this node as subscriber, with no
// acknowledgement; an EVENT carries a publication that is verified before it is
// delivered, and delivered once however many copies arrive, until it expires.

// eventBuffer is how many events a subscription holds that its reader has not
// taken; an event arriving at a full subscription is dropped and counted.
const eventBuffer = 64

// Publication is what Publish sends: the realm and topic, the payload, and its
// time to live, or none for macula's default of 10 minutes.
type Publication struct {
	Realm   [32]byte
	Topic   string
	Payload cbor.Value
	TTLMs   *uint64
}

// Event is a publication a subscription heard, verified: who published it (the
// key id its signature verified under), where, its seq and time, the payload,
// and how it arrived (direct or plumtree).
type Event struct {
	Publisher    [32]byte
	Realm        [32]byte
	Topic        string
	Seq          uint64
	PublishedAt  uint64
	Payload      cbor.Value
	DeliveredVia string
}

// PublicationSeq numbers one publisher's publications: the first is the wall
// clock in microseconds, and each after is one more than the last, or the
// clock, whichever is later, as macula_publication_seq does. Links of one
// identity key share one, so their seqs never repeat.
type PublicationSeq struct {
	mu   sync.Mutex
	last uint64
}

// Next is the seq for the next publication.
func (s *PublicationSeq) Next() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = max(uint64(time.Now().UnixMicro()), s.last+1)
	return s.last
}

// Subscription is one subscription to a realm and topic on a link.
type Subscription struct {
	link   *Link
	key    topicKey
	events chan Event
	once   sync.Once
}

type topicKey struct {
	realm [32]byte
	topic string
}

// Events delivers the subscription's events; it closes when the subscription
// ends, by Unsubscribe or by the link ending.
func (s *Subscription) Events() <-chan Event { return s.events }

// Unsubscribe ends the subscription, and sends UNSUBSCRIBE once no other
// subscription on the link holds its realm and topic.
func (s *Subscription) Unsubscribe() error {
	var err error
	s.once.Do(func() {
		last := s.link.dropSubscription(s)
		close(s.events)
		if last {
			err = s.link.sendTopicFrame(frame.UnsubscribeFrame, s.key)
		}
	})
	return err
}

// NodeID is the node_id this link connected as.
func (l *Link) NodeID() [32]byte { return l.self }

// Publish signs p as a PUBLISH and sends it on the control stream.
func (l *Link) Publish(p Publication) error {
	publish, err := frame.SignPublish(frame.PublicationSpec{
		Realm: p.Realm, Topic: p.Topic, Seq: l.seq.Next(), PublishedAt: uint64(time.Now().UnixMilli()),
		Payload: p.Payload, TTLMs: p.TTLMs,
	}, l.key)
	if err != nil {
		return err
	}
	return l.writer.write(cbor.Encode(publish), MaxFrameBytes)
}

// Subscribe subscribes to topic in realm: the first subscription to a realm
// and topic on the link sends SUBSCRIBE.
func (l *Link) Subscribe(realm [32]byte, topic string) (*Subscription, error) {
	sub := &Subscription{link: l, key: topicKey{realm: realm, topic: topic}, events: make(chan Event, eventBuffer)}
	l.mu.Lock()
	first := len(l.subs[sub.key]) == 0
	l.subs[sub.key] = append(l.subs[sub.key], sub)
	l.mu.Unlock()
	if !first {
		return sub, nil
	}
	if err := l.sendTopicFrame(frame.SubscribeFrame, sub.key); err != nil {
		l.dropSubscription(sub)
		return nil, err
	}
	return sub, nil
}

func (l *Link) sendTopicFrame(build func([]byte, [32]byte, [32]byte) (cbor.Value, error), key topicKey) error {
	v, err := build([]byte(key.topic), key.realm, l.self)
	if err != nil {
		return err
	}
	return l.sendControl(v)
}

// dropSubscription removes sub and reports whether it was the last on its
// realm and topic.
func (l *Link) dropSubscription(sub *Subscription) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.subs[sub.key][:0]
	for _, s := range l.subs[sub.key] {
		if s != sub {
			kept = append(kept, s)
		}
	}
	if len(kept) == 0 {
		delete(l.subs, sub.key)
		return true
	}
	l.subs[sub.key] = kept
	return false
}

// evented delivers an EVENT's publication, once it verifies, to every
// subscription on its realm and topic, unless it was delivered before.
func (l *Link) evented(v cbor.Value) {
	now := time.Now().UnixMilli()
	publication, err := frame.VerifyPublication(v, l.profile, now)
	if err != nil {
		l.count("event_unverified")
		return
	}
	via, _ := fieldOf(v, "delivered_via").AsText()
	event := Event{Publisher: publication.Publisher, Realm: publication.Realm, Topic: publication.Topic,
		Seq: publication.Seq, PublishedAt: publication.PublishedAt, Payload: publication.Payload, DeliveredVia: via}
	if !l.dedup.first(publication.PublicationHash, publication.ExpiresAt, now) {
		l.count("event_duplicate")
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	subs := l.subs[topicKey{realm: publication.Realm, topic: publication.Topic}]
	if len(subs) == 0 {
		l.unrouted["event_unsubscribed"]++
		return
	}
	for _, sub := range subs {
		select {
		case sub.events <- event:
		default:
			l.unrouted["event_overflow"]++
		}
	}
}

// closeSubscriptions ends every subscription when the link ends.
func (l *Link) closeSubscriptions() {
	l.mu.Lock()
	subs := l.subs
	l.subs = map[topicKey][]*Subscription{}
	l.mu.Unlock()
	for _, list := range subs {
		for _, sub := range list {
			sub.once.Do(func() { close(sub.events) })
		}
	}
}
