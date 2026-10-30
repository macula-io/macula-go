package pool

import "github.com/macula-io/macula-go/stationlink"

// DeliveryKind is what a Delivery carries.
type DeliveryKind int

const (
	// KindEvent is an event the subscription heard.
	KindEvent DeliveryKind = iota
	// KindInterrupted says no link carries the subscription any more: events
	// published from FromMs on may be missed until a KindGap follows.
	KindInterrupted
	// KindGap says a link carries the subscription again: events published
	// between FromMs and ToMs may have been missed, so resync it.
	KindGap
)

func (k DeliveryKind) String() string {
	switch k {
	case KindInterrupted:
		return "interrupted"
	case KindGap:
		return "gap"
	}
	return "event"
}

// Delivery is one item a subscription delivers, in the order it delivers
// them: an event, or a notice that events may have been missed.
//
// An Interrupted arrives once when the last link carrying the subscription
// ends, FromMs being when that link last heard from its station and Reason
// why it ended (stationlink.EndReason). A Gap arrives once when a station
// accepts the subscription again, before any event of the link that carries
// it, ToMs being when it did. Neither arrives while another link still
// carries the subscription, nor for an outage a link survives, nor at the
// first subscribe. The times are this node's clock and an event's
// PublishedAt its publisher's: answer a Gap by resyncing the subscription,
// never by dropping events whose PublishedAt falls outside it.
type Delivery struct {
	Kind DeliveryKind
	// Event is the event, for KindEvent.
	Event stationlink.Event
	// FromMs, ToMs and Reason are a notice's, in Unix milliseconds; ToMs is
	// a Gap's alone.
	FromMs uint64
	ToMs   uint64
	Reason string
}

// coverage is the set of links that carry a subscription, from the moment a
// station accepted it there until the link ends, and the notices it owes the
// subscription as that set empties and fills again.
type coverage[K comparable] struct {
	links map[K]struct{}
	// heard is the latest time a link that left the set last heard from its
	// station, since the set last filled again.
	heard       uint64
	interrupted bool
	from        uint64
	reason      string
}

func newCoverage[K comparable]() coverage[K] {
	return coverage[K]{links: map[K]struct{}{}}
}

// covers adds link, accepted at nowMs, and is the Gap owed when it fills a
// set that emptied.
func (c *coverage[K]) covers(link K, nowMs uint64) (Delivery, bool) {
	c.links[link] = struct{}{}
	if !c.interrupted {
		return Delivery{}, false
	}
	c.interrupted, c.heard = false, 0
	return Delivery{Kind: KindGap, FromMs: c.from, ToMs: nowMs, Reason: c.reason}, true
}

// ended removes link, which last heard from its station at heardMs and ended
// for reason, and is the Interrupted owed when that empties the set. A link
// that never carried the subscription changes nothing.
func (c *coverage[K]) ended(link K, heardMs uint64, reason string) (Delivery, bool) {
	if _, held := c.links[link]; !held {
		return Delivery{}, false
	}
	delete(c.links, link)
	c.heard = max(c.heard, heardMs)
	if len(c.links) > 0 {
		return Delivery{}, false
	}
	c.interrupted, c.from, c.reason = true, c.heard, reason
	return Delivery{Kind: KindInterrupted, FromMs: c.from, Reason: reason}, true
}
