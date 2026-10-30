package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/pool"
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

// A full subscription inbox never refuses a notice: its oldest item makes
// room, counted, and the notice arrives as its kind with its times.
func TestAFullSubscriptionInboxTakesANotice(t *testing.T) {
	q := newInbox(dropNewest)
	fill(q, inboxCapacity)
	gap := deliveryItem(pool.Delivery{Kind: pool.KindGap, FromMs: 1000, ToMs: 2000, Reason: "liveness_lost"})
	if !q.push(context.Background(), gap) {
		t.Fatal("a full inbox refused the gap")
	}
	if q.droppedCount() != 1 {
		t.Errorf("dropped %d, want the oldest item counted", q.droppedCount())
	}
	if first, _ := take(t, q, time.Second); first.json != "1" {
		t.Errorf("the first item is %q, want the second filled: the oldest made room", first.json)
	}
	var last inboxItem
	for i := 1; i < inboxCapacity; i++ {
		last, _ = take(t, q, time.Second)
	}
	var notice map[string]any
	if err := json.Unmarshal([]byte(last.json), &notice); err != nil {
		t.Fatalf("the notice %q: %v", last.json, err)
	}
	if notice["kind"] != "gap" || notice["from_ms"] != 1000.0 || notice["to_ms"] != 2000.0 || notice["reason"] != "liveness_lost" {
		t.Errorf("the notice %v", notice)
	}
	interrupted := deliveryItem(pool.Delivery{Kind: pool.KindInterrupted, FromMs: 1000, Reason: "goodbye"})
	if want := `{"from_ms":1000,"kind":"interrupted","reason":"goodbye"}`; interrupted.json != want {
		t.Errorf("an Interrupted is %s, want %s", interrupted.json, want)
	}
	if event := deliveryItem(pool.Delivery{}); event.notice || !strings.Contains(event.json, `"kind":"event"`) {
		t.Errorf("an event is %s, notice %v", event.json, event.notice)
	}
}
