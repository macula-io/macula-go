package pool

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/macula-io/macula-go/stationlink"
)

// subscriptionBuffer is how many deliveries a subscription holds that its
// reader has not taken; an event arriving at a full subscription is dropped and
// counted, and a notice takes the place of the oldest delivery.
const subscriptionBuffer = 256

// Subscription is the node's subscription to a realm and topic, on every link
// the pool holds and every link it dials later. An event is delivered once,
// whichever links hear it, and when no link carries the subscription it says
// so in-band (Delivery).
type Subscription struct {
	pool   *Pool
	realm  [32]byte
	topic  string
	events chan Delivery
	// group is the sealed group the subscription is under, empty for none;
	// its deliveries are taken one at a time from opening and its events
	// opened, since opening may pull a missed epoch from the distributor.
	group   string
	opening chan Delivery
	ctx     context.Context
	cancel  context.CancelFunc

	mu      sync.Mutex
	onLinks map[*stationlink.Link]*stationlink.Subscription
	// attaching is the links a SUBSCRIBE awaits its verdict on.
	attaching map[*stationlink.Link]bool
	cover     coverage[*stationlink.Link]
	ended     bool
	dropped   uint64
	refused   uint64
}

// Subscribe subscribes the node to topic in realm on every link, and on every
// link the pool dials later. It returns once one station acknowledges the
// subscription (macula#12), and fails when none does, leaving no
// subscription: the error joins each link's, in which errors.As finds a
// *stationlink.RefusedError when a station refused it and a
// *stationlink.UnacknowledgedError when one did not answer within 30 seconds.
// With no link up it is ErrNoLink. A sealed
// event arrives once with Unopened "no_group" and no payload (subscribe
// under its group with SubscribeGroup to open it), and a clear event under a
// Required group this node holds is refused and counted.
func (p *Pool) Subscribe(realm [32]byte, topic string) (*Subscription, error) {
	return p.subscribe(realm, topic, "")
}

func (p *Pool) subscribe(realm [32]byte, topic, prefix string) (*Subscription, error) {
	sub := &Subscription{pool: p, realm: realm, topic: topic, events: make(chan Delivery, subscriptionBuffer),
		group: prefix, onLinks: map[*stationlink.Link]*stationlink.Subscription{}, attaching: map[*stationlink.Link]bool{},
		cover: newCoverage[*stationlink.Link]()}
	sub.ctx, sub.cancel = context.WithCancel(p.ctx)
	if prefix != "" {
		sub.opening = make(chan Delivery, subscriptionBuffer)
	}
	if p.isClosed() {
		sub.cancel()
		return nil, ErrClosed
	}
	if sub.opening != nil {
		go sub.open()
	}
	// The pool learns of sub only after the first round, so a link that
	// comes up meanwhile is attached below, never by a replay whose attempt
	// the round would read as its own.
	links := p.links()
	if err := sub.firstAttached(links); err != nil {
		_ = sub.end()
		return nil, err
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = sub.end()
		return nil, ErrClosed
	}
	p.subs[sub] = struct{}{}
	p.mu.Unlock()
	for _, link := range p.links() {
		if !slices.Contains(links, link) {
			go func() { _ = sub.attach(link) }()
		}
	}
	return sub, nil
}

// firstAttached subscribes on every link at once and returns once one station
// acknowledges the subscription, or with every link's error when none does,
// ErrNoLink when no link is up. The links still unanswered then go on.
func (s *Subscription) firstAttached(links []*stationlink.Link) error {
	if len(links) == 0 {
		return ErrNoLink
	}
	results := make(chan error, len(links))
	for _, link := range links {
		go func() { results <- s.attach(link) }()
	}
	var errs []error
	for range links {
		err := <-results
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Events delivers the subscription's events, and the notices that some may
// have been missed (KindInterrupted, then KindGap), in order; it closes when
// the subscription or the pool ends.
func (s *Subscription) Events() <-chan Delivery { return s.events }

// Dropped is how many events arrived while the subscription was full.
func (s *Subscription) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// RefusedClear is how many clear events were refused because a Required
// group this node holds covers their topic.
func (s *Subscription) RefusedClear() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Unsubscribe ends the subscription on every link.
func (s *Subscription) Unsubscribe() error {
	s.pool.mu.Lock()
	delete(s.pool.subs, s)
	s.pool.mu.Unlock()
	return s.end()
}

func (s *Subscription) end() error {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return nil
	}
	s.ended = true
	onLinks := s.onLinks
	s.onLinks = nil
	close(s.events)
	if s.opening != nil {
		close(s.opening)
	}
	s.mu.Unlock()
	s.cancel()
	var errs []error
	for _, linkSub := range onLinks {
		if err := linkSub.Unsubscribe(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// attach subscribes on link, once, and forwards what it hears until the link's
// subscription ends. It returns the link's verdict on the subscription; a
// link it is already attached or attaching to is nil.
func (s *Subscription) attach(link *stationlink.Link) error {
	s.mu.Lock()
	if s.ended || s.onLinks[link] != nil || s.attaching[link] {
		s.mu.Unlock()
		return nil
	}
	s.attaching[link] = true
	s.mu.Unlock()
	linkSub, err := link.Subscribe(s.realm, s.topic)
	s.mu.Lock()
	delete(s.attaching, link)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	if s.ended {
		s.mu.Unlock()
		return linkSub.Unsubscribe()
	}
	s.onLinks[link] = linkSub
	if gap, owed := s.cover.covers(link, uint64(time.Now().UnixMilli())); owed {
		s.notify(gap)
	}
	s.mu.Unlock()
	go s.forward(link, linkSub)
	return nil
}

func (s *Subscription) forward(link *stationlink.Link, linkSub *stationlink.Subscription) {
	for event := range linkSub.Events() {
		if s.opening != nil {
			s.queue(s.opening, Delivery{Kind: KindEvent, Event: event})
			continue
		}
		event, kept := s.opened(s.ctx, event)
		s.deliver(event, kept)
	}
	s.mu.Lock()
	if s.onLinks != nil && s.onLinks[link] == linkSub {
		delete(s.onLinks, link)
		// A closing pool ends its links after its context: that is no
		// interruption, the subscription ends with it.
		interrupted, owed := s.cover.ended(link, link.LastHeard(), stationlink.EndReason(link.Err()))
		if owed && s.ctx.Err() == nil {
			s.notify(interrupted)
		}
	}
	s.mu.Unlock()
}

// queue hands d to ch unless the subscription has ended, dropping and
// counting it when ch is full.
func (s *Subscription) queue(ch chan Delivery, d Delivery) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	select {
	case ch <- d:
	default:
		s.dropped++
	}
}

// notify hands the notice d, under s.mu, to the subscription's next stage,
// in order with its events; a full one gives up its oldest delivery to make
// room, so the reader never misses a notice for a full subscription.
func (s *Subscription) notify(d Delivery) {
	ch := s.events
	if s.opening != nil {
		ch = s.opening
	}
	for {
		select {
		case ch <- d:
			return
		default:
		}
		select {
		case evicted := <-ch:
			if evicted.Kind == KindEvent {
				s.dropped++
			}
		default:
		}
	}
}

// deliver delivers event, or counts it refused.
func (s *Subscription) deliver(event stationlink.Event, kept bool) {
	if !kept {
		s.mu.Lock()
		s.refused++
		s.mu.Unlock()
		return
	}
	s.queue(s.events, Delivery{Kind: KindEvent, Event: event})
}

// open opens a group subscription's events in the order they arrived, and
// passes its notices on in their place among them.
func (s *Subscription) open() {
	for d := range s.opening {
		if d.Kind != KindEvent {
			s.mu.Lock()
			if !s.ended {
				s.notify(d)
			}
			s.mu.Unlock()
			continue
		}
		event, kept := s.opened(s.ctx, d.Event)
		s.deliver(event, kept)
	}
}

// Publish signs pub once and sends it on the first ReplicationFactor links, in
// the pool's selection order, succeeding when one of them takes it. Every copy
// is the same publication, so a subscriber delivers it once. A publish under
// a prefix whose sealed group this node holds is refused as a
// *GroupHeldError: publish under it with PublishGroup.
func (p *Pool) Publish(pub stationlink.Publication) error {
	if keyring := p.heldGroups(); keyring != nil {
		if prefix, _, held := keyring.Policy(pub.Realm, pub.Topic); held {
			return &GroupHeldError{Prefix: prefix}
		}
	}
	return p.publish(pub)
}

func (p *Pool) publish(pub stationlink.Publication) error {
	links := p.links()
	if len(links) == 0 {
		return ErrNoLink
	}
	signed, err := stationlink.SignPublication(p.key, p.shared.PublicationSeq, pub)
	if err != nil {
		return err
	}
	var errs []error
	sent := 0
	for _, link := range links[:min(len(links), p.opts.ReplicationFactor)] {
		if err := link.PublishSigned(signed); err != nil {
			errs = append(errs, err)
			continue
		}
		sent++
	}
	if sent == 0 {
		return errors.Join(errs...)
	}
	return nil
}
