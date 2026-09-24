package stationlink

import "sync"

// EventDedup remembers the publications a node delivered, by publication hash,
// until each expires, so an event heard on several of its links, or twice on
// one, is delivered once. The links of one node share one.
type EventDedup struct {
	mu   sync.Mutex
	seen map[[48]byte]uint64
}

// NewEventDedup is an empty dedup.
func NewEventDedup() *EventDedup {
	return &EventDedup{seen: map[[48]byte]uint64{}}
}

// first reports whether hash is new at nowMs, remembering it until expiresAt,
// and lets go of the hashes that already expired.
func (d *EventDedup) first(hash [48]byte, expiresAt uint64, nowMs int64) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, seen := d.seen[hash]; seen {
		return false
	}
	for held, until := range d.seen {
		if until < uint64(nowMs) {
			delete(d.seen, held)
		}
	}
	d.seen[hash] = expiresAt
	return true
}
