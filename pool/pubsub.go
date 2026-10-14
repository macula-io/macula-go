package pool

import (
	"context"
	"errors"
	"sync"

	"github.com/macula-io/macula-go/stationlink"
)

// subscriptionBuffer is how many events a subscription holds that its reader
// has not taken; one arriving at a full subscription is dropped and counted.
const subscriptionBuffer = 256

// Subscription is the node's subscription to a realm and topic, on every link
// the pool holds and every link it dials later. An event is delivered once,
// whichever links hear it.
type Subscription struct {
	pool   *Pool
	realm  [32]byte
	topic  string
	events chan stationlink.Event
	// group is the sealed group the subscription is under, empty for none;
	// its events are opened one at a time from opening, since opening may
	// pull a missed epoch from the distributor.
	group   string
	opening chan stationlink.Event
	ctx     context.Context
	cancel  context.CancelFunc

	mu      sync.Mutex
	onLinks map[*stationlink.Link]*stationlink.Subscription
	ended   bool
	dropped uint64
	refused uint64
}

// Subscribe subscribes the node to topic in realm on every link. A sealed
// event arrives once with Unopened "no_group" and no payload (subscribe
// under its group with SubscribeGroup to open it), and a clear event under a
// Required group this node holds is refused and counted.
func (p *Pool) Subscribe(realm [32]byte, topic string) (*Subscription, error) {
	return p.subscribe(realm, topic, "")
}

func (p *Pool) subscribe(realm [32]byte, topic, prefix string) (*Subscription, error) {
	sub := &Subscription{pool: p, realm: realm, topic: topic, events: make(chan stationlink.Event, subscriptionBuffer),
		group: prefix, onLinks: map[*stationlink.Link]*stationlink.Subscription{}}
	sub.ctx, sub.cancel = context.WithCancel(p.ctx)
	if prefix != "" {
		sub.opening = make(chan stationlink.Event, subscriptionBuffer)
		go sub.open()
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, ErrClosed
	}
	p.subs[sub] = struct{}{}
	p.mu.Unlock()
	for _, link := range p.links() {
		sub.attach(link)
	}
	return sub, nil
}

// Events delivers the subscription's events; it closes when the subscription
// or the pool ends.
func (s *Subscription) Events() <-chan stationlink.Event { return s.events }

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
// subscription ends.
func (s *Subscription) attach(link *stationlink.Link) {
	s.mu.Lock()
	if s.ended || s.onLinks[link] != nil {
		s.mu.Unlock()
		return
	}
	linkSub, err := link.Subscribe(s.realm, s.topic)
	if err != nil {
		s.mu.Unlock()
		return
	}
	s.onLinks[link] = linkSub
	s.mu.Unlock()
	go s.forward(link, linkSub)
}

func (s *Subscription) forward(link *stationlink.Link, linkSub *stationlink.Subscription) {
	for event := range linkSub.Events() {
		if s.opening != nil {
			s.queue(s.opening, event)
			continue
		}
		event, kept := s.opened(s.ctx, event)
		s.deliver(event, kept)
	}
	s.mu.Lock()
	if s.onLinks != nil && s.onLinks[link] == linkSub {
		delete(s.onLinks, link)
	}
	s.mu.Unlock()
}

// queue hands event to ch unless the subscription has ended, dropping and
// counting it when ch is full.
func (s *Subscription) queue(ch chan stationlink.Event, event stationlink.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return
	}
	select {
	case ch <- event:
	default:
		s.dropped++
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
	s.queue(s.events, event)
}

// open opens a group subscription's events in the order they arrived.
func (s *Subscription) open() {
	for event := range s.opening {
		event, kept := s.opened(s.ctx, event)
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
