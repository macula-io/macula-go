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
	var sub *pool.Subscription
	for sub == nil {
		sub, err = reader.pool.SubscribeGroup(ctx, f.realm.ID, topic, g)
		if reason, _ := group.ReasonOf(err); err != nil && reason != group.ReasonNoDistributor {
			t.Fatalf("subscribe under the group: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatal("the distributor was never found")
		}
	}
	opened := inboxed(reader, sub)
	plainSub, err := subscribe(outsider, f.realm.ID, topic)
	if err != nil {
		t.Fatal(err)
	}
	waitSubscribedOn(t, f, topic, reader, outsider)
	if err := publishGroup(ctx, publisher.pool, f.realm.ID, topic, `{"text": "hello"}`, g, 0); err != nil {
		t.Fatalf("publish under the group: %v", err)
	}
	event := nextEvent(t, opened)
	if event["sealed"] != float64(1) || event["seal_key_id"] != "6100000000000000" || event["unopened"] != nil {
		t.Fatalf("the member's event: %v", event)
	}
	if payload, _ := event["payload"].(map[string]any); payload["text"] != "hello" {
		t.Fatalf("opened to %v", event["payload"])
	}
	plain := nextEvent(t, plainSub)
	if plain["unopened"] != "no_group" || plain["payload"] != nil {
		t.Fatalf("a plain subscription's event: %v", plain)
	}
	err = publish(publisher.pool, f.realm.ID, topic, `"clear"`, 0)
	if e := classify(nil, err); e.kind != kindGroup || e.fields["reason"] != "group_held" {
		t.Fatalf("a clear publish under the held group: %v", err)
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
