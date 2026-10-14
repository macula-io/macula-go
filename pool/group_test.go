package pool

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// Sealed groups end to end through one station: the org's distributor (a
// test stand-in for macula's macula_group_keys) serves group_keys_v1 sealed,
// a member publishes sealed under the group and another opens it, a node the
// distributor refuses gets not_a_member, and a node with no group gets the
// event unopened.

const groupPrefix = "sealed-groups/" + org + "/chat"

type groupWorld struct {
	realm   teststation.Realm
	station *teststation.Station
	epoch   group.Epoch
	refused [32]byte
	pulls   atomic.Int64
}

func newGroupWorld(t *testing.T) *groupWorld {
	t.Helper()
	s := teststation.Start(t, profile.PQPure, "group station")
	realm := teststation.NewRealm(t, profile.PQPure, "sealed-groups", org)
	realm.Admit(t, s, nodeIDOf(t, "group distributor"))
	now := time.Now().UnixMilli()
	w := &groupWorld{realm: realm, station: s, refused: nodeIDOf(t, "group stranger"),
		epoch: group.Epoch{IssuedAt: now - 1_000, PublishUntil: now - 1_000 + group.DefaultRotateAfterMs,
			AcceptUntil: now - 1_000 + group.DefaultRotateAfterMs + 65*60_000}}
	w.epoch.ID[0], w.epoch.Key[0] = 0x51, 0x52
	distributor := connectWith(t, "group distributor", realm, func(o *Opts) { o.KEMAdvertise = true }, s)
	_, err := distributor.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: group.Procedure(org), Confidential: stationlink.ConfidentialRequired,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
			w.pulls.Add(1)
			if !r.Sealed {
				return cbor.Value{}, errors.New("sealed_required")
			}
			if r.Caller == w.refused {
				return cbor.Value{}, errors.New("not_a_member")
			}
			prefix, _ := r.Payload.Get("prefix")
			text, _ := prefix.AsText()
			return group.ReplyValue(group.Reply{Prefix: text, Policy: group.PolicyRequired, Epochs: []group.Epoch{w.epoch}}), nil
		}})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	return w
}

func TestAGroupsEventsTravelSealedAndOpenForMembers(t *testing.T) {
	w := newGroupWorld(t)
	g := Group{Prefix: groupPrefix}
	topic := groupPrefix + "/said_v1"
	member := connect(t, "group member", w.realm, w.station)
	reader := connect(t, "group reader", w.realm, w.station)
	outsider := connect(t, "group outsider", w.realm, w.station)

	sub, err := reader.SubscribeGroup(t.Context(), w.realm.ID, topic, g)
	if err != nil {
		t.Fatalf("SubscribeGroup: %v", err)
	}
	plain, err := outsider.Subscribe(w.realm.ID, topic)
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "both subscribed", func() bool {
		return w.station.Subscribed(reader.NodeID(), w.realm.ID, topic) && w.station.Subscribed(outsider.NodeID(), w.realm.ID, topic)
	})
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("text"), Val: cbor.Text("hello, members")}})
	if err := member.PublishGroup(t.Context(), stationlink.Publication{Realm: w.realm.ID, Topic: topic, Payload: payload}, g); err != nil {
		t.Fatalf("PublishGroup: %v", err)
	}

	opened := next(t, sub)
	if opened.Sealed == nil || opened.Unopened != "" || string(cbor.Encode(opened.Payload)) != string(cbor.Encode(payload)) {
		t.Fatalf("the member's event: sealed %v, unopened %q, payload %v", opened.Sealed != nil, opened.Unopened, opened.Payload)
	}
	if opened.Sealed.KeyID != w.epoch.ID {
		t.Fatalf("sealed under %x, the epoch is %x", opened.Sealed.KeyID, w.epoch.ID)
	}
	unopened := next(t, plain)
	if unopened.Unopened != string(group.ReasonNoGroup) || unopened.Payload.Kind() != 0 {
		t.Fatalf("a subscriber with no group: unopened %q, payload %v", unopened.Unopened, unopened.Payload)
	}

	// The member holds the group: a clear publish under it is refused, and a
	// clear event under its Required prefix is not delivered.
	clear := stationlink.Publication{Realm: w.realm.ID, Topic: topic, Payload: cbor.Text("in the clear")}
	var held *GroupHeldError
	if err := member.Publish(clear); !errors.As(err, &held) || held.Prefix != groupPrefix {
		t.Fatalf("a clear publish under a held group: %v", err)
	}
	if err := outsider.Publish(clear); err != nil {
		t.Fatal(err)
	}
	if next(t, plain).Unopened != "" {
		t.Fatal("the outsider's own clear event came back unopened")
	}
	deadline := time.Now().Add(5 * time.Second)
	for sub.RefusedClear() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if sub.RefusedClear() != 1 {
		t.Fatalf("clear events refused under required: %d", sub.RefusedClear())
	}
}

func TestANodeTheDistributorRefusesIsNotAMember(t *testing.T) {
	w := newGroupWorld(t)
	stranger := connect(t, "group stranger", w.realm, w.station)
	_, err := stranger.SubscribeGroup(t.Context(), w.realm.ID, groupPrefix+"/said_v1", Group{Prefix: groupPrefix})
	if reason, _ := group.ReasonOf(err); reason != group.ReasonNotAMember {
		t.Fatalf("a refused node's join: %v", err)
	}
	if _, err := stranger.SubscribeGroup(t.Context(), w.realm.ID, "sealed-groups/other/x", Group{Prefix: groupPrefix}); !errors.Is(err, group.ErrInvalidGroup) {
		t.Fatalf("a topic outside its group: %v", err)
	}
}

func next(t *testing.T, sub *Subscription) stationlink.Event {
	t.Helper()
	select {
	case e := <-sub.Events():
		return e
	case <-time.After(10 * time.Second):
		t.Fatal("no event")
		return stationlink.Event{}
	}
}
