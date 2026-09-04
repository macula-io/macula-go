package pool

import (
	"sync"
	"time"
)

// dedupKey identifies one inbound EVENT for the purpose of collapsing
// duplicate deliveries — the same fact relayed to this pool by more than
// one link (or seen twice off one link, e.g. after a resubscribe).
//
// Keyed on (Realm, Publisher, Seq, Topic) — deliberately including
// Topic, unlike macula_client.erl's own dedup key of just (Realm,
// Publisher, Seq). That omission is a real, confirmed collision shape:
// an SDK's own auto-published facts and an app's business publish can
// share one seq-counter space per publisher, and without Topic in the
// key a coincidental (publisher, seq) match on two DIFFERENT topics
// collapses into one delivery — the exact bug fixed on the
// macula-station side 2026-09-04. Fixed here from the start rather than
// ported forward.
type dedupKey struct {
	realm     string
	publisher string
	seq       uint64
	topic     string
}

// newDedupKey converts the byte-slice fields to string deliberately —
// Go map keys must be comparable, and slices aren't, so this conversion
// is unavoidable; the point of calling it out is that string(b) compares
// by content, not by the slice header, so two different byte-slice
// allocations holding the identical bytes correctly collide as one key,
// and two different-content slices of the same length do NOT.
func newDedupKey(realm, publisher []byte, seq uint64, topic string) dedupKey {
	return dedupKey{realm: string(realm), publisher: string(publisher), seq: seq, topic: topic}
}

// dedupTable tracks recently seen keys so a duplicate delivery is
// suppressed. Matches macula_client.erl's dedup_window_ms/
// dedup_sweep_ms shape: entries older than window are only reclaimed by
// an explicit Sweep call, not on every Check.
type dedupTable struct {
	mu   sync.Mutex
	seen map[dedupKey]time.Time
}

func newDedupTable() *dedupTable {
	return &dedupTable{seen: make(map[dedupKey]time.Time)}
}

// CheckAndMark reports whether key was already seen and, if not, records
// it as seen at now — check-and-insert as one atomic step, so two
// deliveries racing on the exact same key never both observe "new".
func (d *dedupTable) CheckAndMark(key dedupKey, now time.Time) (duplicate bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.seen[key]; ok {
		return true
	}
	d.seen[key] = now
	return false
}

// Sweep removes every entry older than window relative to now.
func (d *dedupTable) Sweep(now time.Time, window time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for k, t := range d.seen {
		if now.Sub(t) > window {
			delete(d.seen, k)
		}
	}
}

// Len reports the current entry count — test/diagnostic use.
func (d *dedupTable) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
