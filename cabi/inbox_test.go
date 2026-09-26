package main

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func fill(q *inbox, n int) {
	for i := 0; i < n; i++ {
		q.push(context.Background(), inboxItem{json: fmt.Sprint(i)})
	}
}

func take(t *testing.T, q *inbox, wait time.Duration) (inboxItem, inboxState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	return q.next(ctx)
}

func TestInboxHandsOverInOrderThenReportsItsEnd(t *testing.T) {
	q := newInbox(waitForRoom)
	fill(q, 3)
	q.close()
	for i := 0; i < 3; i++ {
		item, state := take(t, q, time.Second)
		if state != inboxItemReady || item.json != fmt.Sprint(i) {
			t.Fatalf("item %d: %q, %v", i, item.json, state)
		}
	}
	if _, state := take(t, q, time.Second); state != inboxClosed {
		t.Fatalf("after the last item: %v, want closed", state)
	}
	if q.push(context.Background(), inboxItem{}) {
		t.Fatal("a closed inbox took an item")
	}
}

func TestInboxWaitsThenReportsEmpty(t *testing.T) {
	q := newInbox(waitForRoom)
	started := time.Now()
	if _, state := take(t, q, 50*time.Millisecond); state != inboxEmpty {
		t.Fatalf("an empty inbox: %v, want empty", state)
	}
	if time.Since(started) < 40*time.Millisecond {
		t.Fatal("next did not wait")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		q.push(context.Background(), inboxItem{json: "late"})
	}()
	if item, state := take(t, q, time.Second); state != inboxItemReady || item.json != "late" {
		t.Fatalf("an item pushed while waiting: %q, %v", item.json, state)
	}
}

func TestFullInboxPolicies(t *testing.T) {
	newest := newInbox(dropNewest)
	fill(newest, inboxCapacity+5)
	if got := newest.droppedCount(); got != 5 {
		t.Errorf("dropNewest dropped %d, want 5", got)
	}
	if item, _ := take(t, newest, time.Second); item.json != "0" {
		t.Errorf("dropNewest kept %q first, want the oldest", item.json)
	}

	oldest := newInbox(dropOldest)
	fill(oldest, inboxCapacity+5)
	if got := oldest.droppedCount(); got != 5 {
		t.Errorf("dropOldest dropped %d, want 5", got)
	}
	if item, _ := take(t, oldest, time.Second); item.json != "5" {
		t.Errorf("dropOldest kept %q first, want 5", item.json)
	}

	waiting := newInbox(waitForRoom)
	fill(waiting, inboxCapacity)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if waiting.push(ctx, inboxItem{json: "late"}) {
		t.Error("waitForRoom took an item with no room")
	}
	pushed := make(chan bool)
	go func() { pushed <- waiting.push(context.Background(), inboxItem{json: "room"}) }()
	take(t, waiting, time.Second)
	select {
	case ok := <-pushed:
		if !ok {
			t.Error("waitForRoom refused an item once there was room")
		}
	case <-time.After(time.Second):
		t.Error("waitForRoom did not take an item once there was room")
	}
}
