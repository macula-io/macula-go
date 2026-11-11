package stationlink

import (
	"sync"

	"github.com/macula-io/macula-go/frame"
)

// The bounds of a link's held set, macula-rust's (src/station_link/pubsub.rs:158-159):
// at most this many publications a link sent are held until the station is
// known to have read them, and at most MaxUnconfirmedBytes of them. Over either,
// the oldest is let go of and counted — the newest always gets in — except that
// the byte cap never lets go of the last one held, so a set can never hold less
// than the newest publication it was given.
const (
	MaxUnconfirmed      = 4096
	MaxUnconfirmedBytes = 32 * 1024 * 1024
)

// The byte cap holds at least one whole frame, which is what makes the bound
// above a ceiling rather than a target: the one publication a full set keeps is
// at most frame.MaxFrameBytes, so no held set exceeds MaxUnconfirmedBytes. This
// does not compile when that stops being true.
var _ [MaxUnconfirmedBytes/frame.MaxFrameBytes - 1]struct{}

// heldPublication is one publication a link sent, with its number on the
// control stream and its size on the wire.
type heldPublication struct {
	number      uint64
	publication SignedPublication
	size        int
}

// unconfirmed holds the publications a link sent that the station is not yet
// known to have read, oldest first (macula-go#78). QUIC delivers the control
// stream in order but the protocol acknowledges no PUBLISH: the station
// answering a frame sent after one is what says it read that one. Should the
// link end first, what is still held may never have arrived, and the pool sends
// it again on another link.
type unconfirmed struct {
	mu    sync.Mutex
	items []heldPublication
	bytes int
	// taken is set once the pool has taken what the link held: nothing holds
	// after that, because nothing would take it again.
	taken bool
}

// hold records p, sent as frame number of size bytes, and answers whether it
// may be written. It is recorded before the first byte goes out, so a link that
// ends in the window before its write still carries it; false is the answer
// once the set has been taken, when the publication belongs to the pool.
// Over either bound the oldest is let go of, answering how many were.
func (u *unconfirmed) hold(number uint64, p SignedPublication, size int) (bool, uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.taken {
		return false, 0
	}
	u.items = append(u.items, heldPublication{number: number, publication: p, size: size})
	u.bytes += size
	var letGo uint64
	for len(u.items) > MaxUnconfirmed || (u.bytes > MaxUnconfirmedBytes && len(u.items) > 1) {
		u.bytes -= u.items[0].size
		u.items = u.items[1:]
		letGo++
	}
	return true, letGo
}

// drop removes the hold of frame number, answering whether it was still held:
// false means the pool took it, and carries the publication from there.
func (u *unconfirmed) drop(number uint64) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	for i, held := range u.items {
		if held.number != number {
			continue
		}
		u.items = append(u.items[:i], u.items[i+1:]...)
		u.bytes -= held.size
		return true
	}
	return false
}

// confirmBefore lets go of every publication sent before frame number: the
// station answered that frame, so it read them.
func (u *unconfirmed) confirmBefore(number uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for len(u.items) > 0 && u.items[0].number < number {
		u.bytes -= u.items[0].size
		u.items = u.items[1:]
	}
}

// take is every publication still held, oldest first, leaving none. Nothing is
// held after it: a write that has not started yet is refused.
func (u *unconfirmed) take() []SignedPublication {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.taken = true
	u.bytes = 0
	held := make([]SignedPublication, len(u.items))
	for i, item := range u.items {
		held[i] = item.publication
	}
	u.items = nil
	return held
}

// TakeUnconfirmed is the publications the link sent that the station is not
// known to have read, oldest first, leaving none. Once the link has ended these
// may never have arrived: the pool sends them again on another link, where a
// subscriber that did receive one delivers it once all the same, since it is
// the same signed publication (macula-go#78).
func (l *Link) TakeUnconfirmed() []SignedPublication { return l.unconfirmed.take() }
