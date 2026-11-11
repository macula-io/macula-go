package stationlink

import (
	"context"
	"crypto/sha512"
	"errors"
	"sync"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// PubSub, as macula 12's link does it. A PUBLISH carries a publication signed
// with the link's identity key; SUBSCRIBE and UNSUBSCRIBE are control frames
// naming the realm, the topic (as bytes) and this node as subscriber, each
// answered with a REGISTER_ACK (register.go); an EVENT carries a publication that is verified before it is
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
	// Seal, when set, seals Payload once the publication's seq and time are
	// known, and the PUBLISH carries what it returns in place of the payload
	// (a sealed group's event, package group).
	Seal func(SealFields) (frame.Sealed, error)
}

// SealFields are what a sealed event is bound to: the publication's routing
// fields, its publisher included, and the payload to seal.
type SealFields struct {
	Realm       [32]byte
	Topic       string
	Publisher   [32]byte
	Seq         uint64
	PublishedAt uint64
	Payload     cbor.Value
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
	// Sealed is a sealed event's payload, nil for a clear one; a sealed
	// event's Payload is null until a group subscription opens it.
	Sealed *frame.Sealed
	// Unopened is why a sealed event could not be opened, empty for one that
	// was opened or is clear: one of package group's reasons. Such an event
	// is delivered once, with nothing of its payload.
	Unopened string
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
	signed, err := SignPublication(l.key, l.seq, p)
	if err != nil {
		return err
	}
	return l.PublishSigned(signed)
}

// SignedPublication is a PUBLISH signed once, to be sent on several links of
// one node: every copy is the same publication, so a subscriber hearing it on
// several links delivers it once.
type SignedPublication struct {
	encoded []byte
	// resendUntil is the last moment a re-send can still land, in Unix
	// milliseconds: past it a subscriber would refuse it (frame.ResendUntil).
	resendUntil uint64
	// identity is the SHA-384 of the signed bytes: every copy of one
	// publication, on whichever link, carries the same, which is how a pool
	// recognises a copy of one it already carried (macula-go#78).
	identity [48]byte
}

// Identity is what tells this publication from another: the SHA-384 of its
// signed bytes, the same value frame.VerifiedPublication.PublicationHash is for
// a subscriber.
func (p SignedPublication) Identity() [48]byte { return p.identity }

// ResendUntil is the last moment, in Unix milliseconds, this publication can be
// sent again and still be delivered.
func (p SignedPublication) ResendUntil() uint64 { return p.resendUntil }

// Size is the publication's size on the wire, in bytes.
func (p SignedPublication) Size() int { return len(p.encoded) }

// SignPublication signs p with key at the next seq of seq, as Publish does.
func SignPublication(key *identity.NodeKey, seq *PublicationSeq, p Publication) (SignedPublication, error) {
	spec := frame.PublicationSpec{
		Realm: p.Realm, Topic: p.Topic, Seq: seq.Next(), PublishedAt: uint64(time.Now().UnixMilli()),
		Payload: p.Payload, TTLMs: p.TTLMs,
	}
	if p.Seal != nil {
		sealed, err := p.Seal(SealFields{Realm: spec.Realm, Topic: spec.Topic, Publisher: key.KeyID(), Seq: spec.Seq,
			PublishedAt: spec.PublishedAt, Payload: p.Payload})
		if err != nil {
			return SignedPublication{}, err
		}
		spec.Sealed = &sealed
	}
	publish, err := frame.SignPublish(spec, key)
	if err != nil {
		return SignedPublication{}, err
	}
	encoded := cbor.Encode(publish)
	return SignedPublication{encoded: encoded, resendUntil: frame.ResendUntil(spec.PublishedAt, spec.TTLMs),
		identity: sha512.Sum384(encoded)}, nil
}

// AfterHeld runs between recording a publication's hold and writing its first
// byte, the one window in which a frame is held and not yet written. It is a
// variable only so that a test can end the link there (macula-go#78); nil in a
// build.
var AfterHeld func()

// PublishSigned sends a publication SignPublication signed, as it is. Sign
// with the node's own identity key: the publisher a subscriber hears is the
// key that signed it, whichever link carried it.
//
// The frame is held before its first byte goes out, until a frame the station
// answers proves it read it (unconfirmed.go). It answers nil when a link's
// stream took the frame whole, or when the frame will be carried again by the
// pool — because part of it went out, or because the pool took the held copy
// while it was being written. An error says nothing was written and nothing is
// held, so the caller may send the same publication elsewhere.
func (l *Link) PublishSigned(p SignedPublication) error {
	var letGo uint64
	number, n, err := l.writer.writeNumbered(p.encoded, MaxFrameBytes, func(number uint64) bool {
		held, dropped := l.unconfirmed.hold(number, p, len(p.encoded))
		letGo = dropped
		if held && AfterHeld != nil {
			AfterHeld()
		}
		return held
	})
	if letGo > 0 {
		l.count("publication_unconfirmed_let_go")
	}
	switch {
	case errors.Is(err, ErrFrameTooLarge):
		// Refused before it was numbered: nothing of it was held or written.
		return l.namedEnding(err)
	case errors.Is(err, errFrameRefused):
		// The link ended and the pool took what it held: nothing was written.
		return l.namedEnding(err)
	case err == nil:
		return nil
	case n == 0:
		// Nothing went out. If the hold is still here, nothing anywhere carries
		// this frame; if it is gone, the pool took it and the hand-over will.
		if l.unconfirmed.drop(number) {
			return l.namedEnding(err)
		}
		return nil
	default:
		// A prefix of the frame is on a stream that is broken: the station will
		// not route it, and the held copy is the one that counts.
		endLink(l, err)
		return nil
	}
}

// Subscribe subscribes to topic in realm. The first subscription to a realm
// and topic on the link sends SUBSCRIBE and returns once the station
// acknowledges it (macula#12), within 30 seconds: a refusal is a
// *RefusedError, no answer an *UnacknowledgedError (and the link sends
// UNSUBSCRIBE, so a late acceptance does not linger), and either leaves no
// subscription. A subscription made while that SUBSCRIBE awaits its answer
// returns the same verdict; one made after it was accepted returns at once.
func (l *Link) Subscribe(realm [32]byte, topic string) (*Subscription, error) {
	sub := &Subscription{link: l, key: topicKey{realm: realm, topic: topic}, events: make(chan Event, eventBuffer)}
	l.mu.Lock()
	first := len(l.subs[sub.key]) == 0
	l.subs[sub.key] = append(l.subs[sub.key], sub)
	pending := l.subscribing[sub.key]
	if first {
		pending = &pendingSubscribe{done: make(chan struct{})}
		l.subscribing[sub.key] = pending
	}
	l.mu.Unlock()
	switch {
	case first:
		l.subscribeAnswered(sub.key, pending, l.subscribed(sub.key))
	case pending != nil:
		<-pending.done
	}
	if pending != nil && pending.err != nil {
		return nil, pending.err
	}
	return sub, nil
}

// pendingSubscribe is a SUBSCRIBE awaiting its REGISTER_ACK; done closes once
// err holds the verdict.
type pendingSubscribe struct {
	done chan struct{}
	err  error
}

// subscribed sends SUBSCRIBE for key, naming this node as subscriber, and
// waits for the station's verdict.
func (l *Link) subscribed(key topicKey) error {
	r := registration{kind: "subscribe", realm: key.realm, name: key.topic, subscriber: l.self}
	answer := l.expect(r)
	if err := l.sendTopicFrame(frame.SubscribeFrame, key); err != nil {
		l.forget(r, answer)
		return l.namedEnding(err)
	}
	return l.verdict(context.Background(), r, answer)
}

// subscribeAnswered settles a SUBSCRIBE's verdict. One that does not hold
// drops every subscription to key, each of which waited on it, and an
// unanswered one is withdrawn first, while later subscribers still wait, so no
// UNSUBSCRIBE follows a SUBSCRIBE of theirs.
func (l *Link) subscribeAnswered(key topicKey, pending *pendingSubscribe, err error) {
	var silent *UnacknowledgedError
	if errors.As(err, &silent) {
		_ = l.sendTopicFrame(frame.UnsubscribeFrame, key)
	}
	l.mu.Lock()
	pending.err = err
	delete(l.subscribing, key)
	if err != nil {
		delete(l.subs, key)
	}
	l.mu.Unlock()
	close(pending.done)
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
	via := frame.DeliveredVia(v)
	if publication.Sealed != nil {
		publication.Payload = cbor.Null()
	}
	event := Event{Publisher: publication.Publisher, Realm: publication.Realm, Topic: publication.Topic,
		Seq: publication.Seq, PublishedAt: publication.PublishedAt, Payload: publication.Payload, DeliveredVia: via,
		Sealed: publication.Sealed}
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
