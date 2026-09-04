package pool

import (
	"time"

	"github.com/macula-io/macula-go/frame"
)

// Subscribe registers handler for every EVENT matching (realm, topic).
// The first local subscriber for a given (realm, topic) issues a wire
// SUBSCRIBE on every currently-connected link (and, via watchLinks, on
// every link that connects or reconnects afterward); an additional
// local subscriber to the same (realm, topic) registers for delivery
// without any new wire traffic -- matches macula_client.erl's own
// issue_wire_subs/AlreadyTracked check.
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
		p.issueWireSubscribe(realm, topic)
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

func (p *Pool) issueWireSubscribe(realm []byte, topic string) {
	spec := frame.NewSubscribeSpec(topic, realm, p.opts.Identity.NodeID())
	for _, a := range p.connectedActors() {
		_ = a.send(p.ctx, subscribeCmd{spec: spec})
	}
}

// watchLinks drains link lifecycle notifications. Its only job on an
// "up" transition is replay: re-issue a wire SUBSCRIBE for every
// currently-tracked (realm, topic) onto the freshly (re)connected
// actor — the actor itself never remembers what it carried before dying,
// matching macula_client.erl's own split (macula_client_replay pushes
// state from the pool onto the fresh link; the link doesn't remember its
// own past).
func (p *Pool) watchLinks() {
	for {
		select {
		case <-p.ctx.Done():
			return
		case ev := <-p.linkEvent:
			if ev.up {
				p.replayOnto(ev.actor)
			}
		}
	}
}

func (p *Pool) replayOnto(a *actor) {
	p.subsMu.Lock()
	keys := make([]topicKey, 0, len(p.topicIndex))
	for k := range p.topicIndex {
		keys = append(keys, k)
	}
	p.subsMu.Unlock()

	for _, k := range keys {
		spec := frame.NewSubscribeSpec(k.topic, []byte(k.realm), p.opts.Identity.NodeID())
		_ = a.send(p.ctx, subscribeCmd{spec: spec})
	}
}

// fanoutEvents drains parsed inbound EVENTs from every link's actor,
// dedupes, and delivers to matching local subscribers. Each delivery
// runs on its own goroutine -- a slow or panicking EventHandler must
// never stall dispatch for every other subscriber and link, the same
// "never block the dispatch path on user code" reasoning actor.go
// applies to inbound CALLs.
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
	key := newDedupKey(evt.realm, evt.publisher, evt.seq, evt.topic)
	if p.dedup.CheckAndMark(key, time.Now()) {
		return
	}

	tk := topicKey{realm: string(evt.realm), topic: evt.topic}
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
		go h(evt.realm, evt.topic, evt.payload)
	}
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
