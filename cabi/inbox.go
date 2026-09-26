package main

// #include <stdint.h>
import "C"

import (
	"context"
	"sync"
)

// The library never calls into a binding: what arrives on its own (a
// subscription's events, a served procedure's calls and sessions, a pool's
// link events) waits in an inbox owned by its handle, and the binding takes
// it with a *_next call (CONTRACT.md "Inboxes").

// inboxItem is one thing handed over: its JSON, and the handle it comes with
// (a pending call or a stream), or 0.
type inboxItem struct {
	handle C.uintptr_t
	json   string
}

// fullPolicy is what an inbox does with an item when it is full.
type fullPolicy int

const (
	// waitForRoom makes the pusher wait until there is room, its context
	// ends, or the inbox closes: a served call waits until its deadline.
	waitForRoom fullPolicy = iota
	// dropNewest refuses the item and counts it: a subscription's events.
	dropNewest
	// dropOldest makes room by dropping the oldest item: a pool's link
	// events, where the latest state matters most.
	dropOldest
)

// inboxCapacity is how many items wait before the policy applies.
const inboxCapacity = 256

// inbox is a bounded queue with an end. A closed inbox still hands over what
// it holds before next reports that it ended.
type inbox struct {
	policy  fullPolicy
	mu      sync.Mutex
	items   []inboxItem
	closed  bool
	dropped uint64
	// ready is signalled (without blocking) when an item arrives or the
	// inbox closes; room when an item is taken or the inbox closes.
	ready chan struct{}
	room  chan struct{}
}

func newInbox(policy fullPolicy) *inbox {
	return &inbox{policy: policy, ready: make(chan struct{}, 1), room: make(chan struct{}, 1)}
}

func signal(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

// push hands item over, and reports whether the inbox took it: false when it
// closed, when it was full under dropNewest, or when ctx ended while waiting
// for room.
func (q *inbox) push(ctx context.Context, item inboxItem) bool {
	for {
		q.mu.Lock()
		switch {
		case q.closed:
			q.mu.Unlock()
			return false
		case len(q.items) < inboxCapacity:
			q.items = append(q.items, item)
			q.mu.Unlock()
			signal(q.ready)
			return true
		case q.policy == dropNewest:
			q.dropped++
			q.mu.Unlock()
			return false
		case q.policy == dropOldest:
			q.items = append(q.items[1:], item)
			q.dropped++
			q.mu.Unlock()
			signal(q.ready)
			return true
		}
		q.mu.Unlock()
		select {
		case <-q.room:
		case <-ctx.Done():
			return false
		}
	}
}

// inboxState is what a next call found.
type inboxState int

const (
	inboxItemReady inboxState = iota // an item was taken
	inboxEmpty                       // ctx ended with nothing to take
	inboxClosed                      // the inbox ended and holds nothing more
)

// next takes the next item, waiting until one arrives, the inbox closes, or
// ctx ends.
func (q *inbox) next(ctx context.Context) (inboxItem, inboxState) {
	for {
		q.mu.Lock()
		switch {
		case len(q.items) > 0:
			item := q.items[0]
			q.items = q.items[1:]
			more := len(q.items) > 0 || q.closed
			q.mu.Unlock()
			signal(q.room)
			if more {
				signal(q.ready)
			}
			return item, inboxItemReady
		case q.closed:
			q.mu.Unlock()
			signal(q.ready)
			return inboxItem{}, inboxClosed
		}
		q.mu.Unlock()
		select {
		case <-q.ready:
		case <-ctx.Done():
			return inboxItem{}, inboxEmpty
		}
	}
}

// close ends the inbox; it is safe to call more than once. Items it holds
// are still handed over.
func (q *inbox) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	signal(q.ready)
	signal(q.room)
}

// droppedCount is how many items the inbox dropped.
func (q *inbox) droppedCount() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// takeNext is a *_next export's result: the item's JSON (and its handle
// through handleOut, when given), or NULL with *closed telling an end (1)
// from a wait that ran out (0). A wait ended by its cancel token is the error
// kind cancelled; one ended by its timeout is not an error.
func takeNext(q *inbox, token C.uintptr_t, timeoutMs C.int64_t, handleOut *C.uintptr_t, closed *C.int32_t,
	errOut **C.char) *C.char {
	*closed = 0
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	defer cancel()
	item, state := q.next(ctx)
	switch state {
	case inboxItemReady:
		if handleOut != nil {
			*handleOut = item.handle
		}
		return cString(item.json)
	case inboxClosed:
		*closed = 1
	case inboxEmpty:
		if context.Cause(ctx) == errTokenCancelled {
			setErr(errOut, newError(kindCancelled, "the wait was cancelled"))
		}
	}
	return nil
}
