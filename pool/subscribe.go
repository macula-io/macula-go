package pool

import (
	"time"

	"github.com/macula-io/macula-go/cbor"
)

// Subscribe registers handler for every EVENT matching (realm, topic), where
// a "*" segment in topic matches any one segment, as the station matches it.
// The first local subscriber for a given (realm, topic) subscribes every
// currently-connected link (and, via watchLinks, every link that connects
// or reconnects afterward); an additional local subscriber to the same
// (realm, topic) registers for delivery without any new wire traffic --
// matches macula_client.erl's own issue_wire_subs/AlreadyTracked check.
func (p *Pool) Subscribe(realm []byte, topic string, handler EventHandler) SubID {
	key := topicKey{realm: string(realm), topic: topic}

	p.subsMu.Lock()
	id := SubID(p.nextSubID.Add(1))
	p.subs[id] = &subSpec{realm: realm, topic: topic, handler: handler}
	set, alreadyTracked := p.topicIndex[key]
	if !alreadyTracked {
		set = make(map[SubID]struct{})
		p.topicIndex[key] = set
	}
	set[id] = struct{}{}
	p.subsMu.Unlock()

	if !alreadyTracked {
		p.subscribeLinks(key)
	}
	return id
}

// Unsubscribe drops a subscription. Idempotent. Matches
// macula_client.erl's own documented choice to leave the underlying wire
// subscription in place for the pool's lifetime even after the last
// local subscriber drops -- multiple local subscribers to one (realm,
// topic) already multiplex over ONE wire subscription per link, so
// tearing it down on last-unsubscribe would only save a station-side
// registration the pool may well re-need, at the cost of matching
// behavior the reference deliberately doesn't implement either.
func (p *Pool) Unsubscribe(id SubID) {
	p.subsMu.Lock()
	spec, ok := p.subs[id]
	if !ok {
		p.subsMu.Unlock()
		return
	}
	delete(p.subs, id)
	key := topicKey{realm: string(spec.realm), topic: spec.topic}
	if set, ok := p.topicIndex[key]; ok {
		delete(set, id)
		if len(set) == 0 {
			delete(p.topicIndex, key)
		}
	}
	p.subsMu.Unlock()
}

// subscribeLinks subscribes every connected link to key, each on its own
// goroutine: a session can take up to its send timeout to write a
// SUBSCRIBE, and one stalled link must not hold up Subscribe.
func (p *Pool) subscribeLinks(key topicKey) {
	for _, ls := range p.connectedSessions() {
		go ls.subscribe(key)
	}
}

// watchLinks drains link lifecycle notifications. Its only job on an
// "up" transition is replay: subscribe the freshly (re)connected session
// to every currently-tracked (realm, topic) — a session never remembers
// what the link's previous one carried, matching macula_client.erl's own
// split (macula_client_replay pushes state from the pool onto the fresh
// link; the link doesn't remember its own past). Replay runs on its own
// goroutine for the same reason subscribeLinks does.
func (p *Pool) watchLinks() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case ev := <-p.linkEvent:
			if ev.up {
				go p.replayOnto(ev.session)
			}
			if p.opts.OnLinkEvent != nil {
				// Per-event goroutine, same as deliverOne's own choice
				// for event delivery -- fire-and-forget, deliberately
				// not tracked in p.wg (Close doesn't wait for it,
				// matching event delivery's own documented
				// non-guarantee), and NOT ordered relative to other
				// link-event callbacks: a link flapping quickly can
				// call this with "down" before an earlier "up" is
				// observed by the caller. Needs recover() for the same
				// reason deliverOne does -- an unrecovered panic in ANY
				// goroutine kills the whole process, and this runs
				// caller-supplied code.
				go callOnLinkEvent(p.opts.OnLinkEvent, ev.link.key, ev.up, ev.err)
			}
		}
	}
}

func (p *Pool) replayOnto(ls *linkSession) {
	p.subsMu.Lock()
	keys := make([]topicKey, 0, len(p.topicIndex))
	for k := range p.topicIndex {
		keys = append(keys, k)
	}
	p.subsMu.Unlock()

	for _, k := range keys {
		ls.subscribe(k)
	}
}

// fanoutEvents drains the EVENTs every link's subscriptions forward,
// dedupes, and delivers to matching local subscribers. Each delivery runs
// on its own goroutine -- a slow or panicking EventHandler must never
// stall dispatch for every other subscriber and link.
func (p *Pool) fanoutEvents() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case evt := <-p.events:
			p.deliver(evt)
		}
	}
}

func (p *Pool) deliver(evt inboundEvent) {
	key := newDedupKey(evt.pattern, evt.realm, evt.publisher, evt.seq, evt.topic)
	if p.dedup.CheckAndMark(key, time.Now()) {
		return
	}

	// The subscription that received the event already matched it, "*"
	// segments included, so its pattern is looked up exactly.
	tk := topicKey{realm: string(evt.realm), topic: evt.pattern}
	p.subsMu.Lock()
	set := p.topicIndex[tk]
	handlers := make([]EventHandler, 0, len(set))
	for id := range set {
		if s, ok := p.subs[id]; ok {
			handlers = append(handlers, s.handler)
		}
	}
	p.subsMu.Unlock()

	for _, h := range handlers {
		go deliverOne(h, evt.realm, evt.topic, evt.payload)
	}
}

// deliverOne runs one EventHandler on its own goroutine, recovering a
// panic instead of letting it propagate — an unrecovered panic in ANY
// goroutine terminates the whole process in Go, unlike Erlang's
// per-process crash isolation (macula_client.erl's own deliver_one is a
// plain, non-blocking `Pid ! Msg` specifically because the receiving
// process's own supervision handles a bad handler; Go's `go h(...)` has
// no such safety net built in). A subscriber's own bug must cost that
// one delivery, never every other link and subscriber this pool is
// carrying.
func deliverOne(h EventHandler, realm []byte, topic string, payload cbor.Value) {
	defer func() { recover() }()
	h(realm, topic, payload)
}

// callOnLinkEvent runs one Opts.OnLinkEvent callback on its own
// goroutine, recovering a panic for the same reason deliverOne does.
func callOnLinkEvent(cb func(string, bool, error), linkKey string, up bool, err error) {
	defer func() { recover() }()
	cb(linkKey, up, err)
}

func (p *Pool) sweepDedup() {
	ticker := time.NewTicker(p.opts.DedupSweep)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.dedup.Sweep(time.Now(), p.opts.DedupWindow)
		}
	}
}
