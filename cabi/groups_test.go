package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// Sealed groups through the ABI: a stand-in for the org's distributor
// (macula's macula_group_keys) serves group_keys_v1 sealed; one node
// publishes under the group, another opens the event, a plain subscription
// gets it unopened, and refusals come back as kind group with their reason.

func TestGroupOptionsAreChecked(t *testing.T) {
	for _, text := range []string{``, `{}`, `{"prefix":""}`, `{"prefix":"r/o","distributor":"00"}`, `{"prefix":"r/o","grant":"t"}`} {
		if _, err := groupOf(text); kindOf(err) != kindInvalidArgument {
			t.Errorf("group options %q: %v, want invalid_argument", text, err)
		}
	}
	g, err := groupOf(`{"prefix":"r/o/chat","ucan":"t","distributor":"` + strings.Repeat("ab", 32) + `"}`)
	if err != nil || g.Prefix != "r/o/chat" || string(g.UCAN) != "t" || g.Distributor == nil || g.Distributor[0] != 0xab {
		t.Errorf("group options: %+v, %v", g, err)
	}
}

func TestGroupErrorsClassify(t *testing.T) {
	refused := &group.Error{Reason: group.ReasonNotAMember, Err: errors.New("handler_error")}
	if e := classify(nil, refused); e.kind != kindGroup || e.fields["reason"] != "not_a_member" {
		t.Errorf("a refused join: %s", e.JSON())
	}
	if e := classify(nil, &pool.GroupHeldError{Prefix: "r/o/chat"}); e.kind != kindGroup || e.fields["reason"] != "group_held" || e.fields["prefix"] != "r/o/chat" {
		t.Errorf("a clear publish under a held group: %s", e.JSON())
	}
	if e := classify(nil, group.ErrInvalidGroup); e.kind != kindInvalidArgument {
		t.Errorf("an invalid group: %s", e.JSON())
	}
}

func TestASealedGroupThroughTheABI(t *testing.T) {
	f := newFleet(t, "groupabi")
	distributor := f.joinKeyed(t, "group abi distributor")
	f.realm.Admit(t, f.stations[0], distributor.pool.NodeID())
	serveGroupDistributor(t, f, distributor)
	publisher := f.join(t, "group abi publisher", f.stations[0])
	reader := f.join(t, "group abi reader", f.stations[1])
	// The test stations relay no publication between them: the outsider
	// hears the publisher's station.
	outsider := f.join(t, "group abi outsider", f.stations[0])
	prefix := f.realm.Name + "/" + f.realm.Org + "/chat"
	topic := prefix + "/said_v1"
	g, err := groupOf(`{"prefix":"` + prefix + `"}`)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	opened := subscribeGroupUntilFound(ctx, t, reader, f, topic, g)
	plainSub, err := subscribe(outsider, f.realm.ID, topic)
	if err != nil {
		t.Fatal(err)
	}
	waitSubscribedOn(t, f, topic, reader, outsider)
	if err := publishGroup(ctx, publisher.pool, f.realm.ID, topic, `{"text": "hello"}`, g, 0); err != nil {
		t.Fatalf("publish under the group: %v", err)
	}
	assertGroupMemberEvent(t, nextEvent(t, opened))
	assertPlainEventUnopened(t, nextEvent(t, plainSub))
	err = publish(publisher.pool, f.realm.ID, topic, `"clear"`, 0)
	if e := classify(nil, err); e.kind != kindGroup || e.fields["reason"] != "group_held" {
		t.Fatalf("a clear publish under the held group: %v", err)
	}
}

// serveGroupDistributor stands in for the org's distributor: it serves
// group_keys_v1 sealed and answers with the epoch the group is opened under.
func serveGroupDistributor(t *testing.T, f fleet, distributor *livePool) {
	t.Helper()
	now := time.Now().UnixMilli()
	epoch := group.Epoch{IssuedAt: now - 1_000, PublishUntil: now - 1_000 + group.DefaultRotateAfterMs,
		AcceptUntil: now - 1_000 + group.DefaultRotateAfterMs + 65*60_000}
	epoch.ID[0], epoch.Key[0] = 0x61, 0x62
	if _, err := distributor.pool.Serve(context.Background(), pool.Offer{Realm: f.realm.ID, Procedure: group.Procedure(f.realm.Org),
		Confidential: stationlink.ConfidentialRequired, Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			prefix, _ := r.Payload.Get("prefix")
			text, _ := prefix.AsText()
			return group.ReplyValue(group.Reply{Prefix: text, Policy: group.PolicyRequired, Epochs: []group.Epoch{epoch}}), nil
		}}); err != nil {
		t.Fatal(err)
	}
}

// subscribeGroupUntilFound subscribes under the group until the distributor's
// advertisement reaches the reader's station.
func subscribeGroupUntilFound(ctx context.Context, t *testing.T, reader *livePool, f fleet, topic string, g pool.Group) *subscription {
	t.Helper()
	for {
		sub, err := reader.pool.SubscribeGroup(ctx, f.realm.ID, topic, g)
		if reason, _ := group.ReasonOf(err); err != nil && reason != group.ReasonNoDistributor {
			t.Fatalf("subscribe under the group: %v", err)
		}
		if sub != nil {
			return inboxed(reader, sub)
		}
		if ctx.Err() != nil {
			t.Fatal("the distributor was never found")
		}
	}
}

// assertGroupMemberEvent checks a member's event came sealed under the
// distributor's epoch key and opened to its payload.
func assertGroupMemberEvent(t *testing.T, event map[string]any) {
	t.Helper()
	if event["sealed"] != float64(1) || event["seal_key_id"] != "6100000000000000" || event["unopened"] != nil {
		t.Fatalf("the member's event: %v", event)
	}
	if payload, _ := event["payload"].(map[string]any); payload["text"] != "hello" {
		t.Fatalf("opened to %v", event["payload"])
	}
}

// assertPlainEventUnopened checks a plain subscription's event carries no
// group opening.
func assertPlainEventUnopened(t *testing.T, event map[string]any) {
	t.Helper()
	if event["unopened"] != "no_group" || event["payload"] != nil {
		t.Fatalf("a plain subscription's event: %v", event)
	}
}

func waitSubscribedOn(t *testing.T, f fleet, topic string, pools ...*livePool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, lp := range pools {
		for !(f.stations[0].Subscribed(lp.pool.NodeID(), f.realm.ID, topic) || f.stations[1].Subscribed(lp.pool.NodeID(), f.realm.ID, topic)) {
			if time.Now().After(deadline) {
				t.Fatal("never subscribed")
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func nextEvent(t *testing.T, s *subscription) map[string]any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	item, state := s.box.next(ctx)
	if state != inboxItemReady {
		t.Fatal("no event")
	}
	var event map[string]any
	if err := json.Unmarshal([]byte(item.json), &event); err != nil {
		t.Fatal(err)
	}
	return event
}
