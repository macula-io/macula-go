package group

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/stationlink"
)

const prefix = "io.macula/acme/chat"

var realm = [32]byte{0xab}

// fake is a distributor, a clock and a timer: pulls answer from the epochs
// it serves, or its refusal, and timers fire only when the test says.
type fake struct {
	mu       sync.Mutex
	now      int64
	policy   Policy
	served   []Epoch
	refuse   string
	failWith error
	pulls    []Pull
	timers   []func()
	delays   []time.Duration
}

func (f *fake) pull(_ context.Context, p Pull) (cbor.Value, [32]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pulls = append(f.pulls, p)
	if f.failWith != nil {
		return cbor.Value{}, [32]byte{}, f.failWith
	}
	if f.refuse != "" {
		detail := f.refuse
		return cbor.Value{}, [32]byte{}, &stationlink.ProviderError{Code: "handler_error", Detail: &detail}
	}
	epochs := f.served
	if id, ok := p.Payload.Get("epoch"); ok {
		if b, isID := id.AsBytes(); isID {
			epochs = nil
			for _, e := range f.served {
				if bytes.Equal(e.ID[:], b) {
					epochs = []Epoch{e}
				}
			}
			if epochs == nil {
				detail := "unknown_epoch"
				return cbor.Value{}, [32]byte{}, &stationlink.ProviderError{Code: "handler_error", Detail: &detail}
			}
		}
	}
	return ReplyValue(Reply{Prefix: prefix, Policy: f.policy, Epochs: epochs}), [32]byte{0xd1}, nil
}

func (f *fake) keyring() *Keyring {
	return NewKeyring(Options{
		Pull:    f.pull,
		Now:     func() int64 { f.mu.Lock(); defer f.mu.Unlock(); return f.now },
		Uniform: func() float64 { return 0.5 },
		AfterFunc: func(d time.Duration, fn func()) func() bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.timers = append(f.timers, fn)
			f.delays = append(f.delays, d)
			return func() bool { return true }
		},
	})
}

func (f *fake) pullCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pulls)
}

// fire runs the newest timer, as its wake-up would.
func (f *fake) fire() {
	f.mu.Lock()
	fn := f.timers[len(f.timers)-1]
	f.mu.Unlock()
	fn()
}

func (f *fake) lastDelay() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.delays[len(f.delays)-1]
}

func epochAt(id byte, issued int64) Epoch {
	e := Epoch{IssuedAt: issued, PublishUntil: issued + DefaultRotateAfterMs, AcceptUntil: issued + DefaultRotateAfterMs + eventLifeMs}
	e.ID[0], e.Key[0] = id, id
	return e
}

func newFake() *fake {
	return &fake{now: 1_000_000, policy: PolicyRequired, served: []Epoch{epochAt(1, 1_000_000)}}
}

func TestJoinPullsOnceAndHolds(t *testing.T) {
	f := newFake()
	k := f.keyring()
	policy, err := k.Join(context.Background(), realm, prefix, JoinOptions{UCAN: []byte("grant")})
	if err != nil || policy != PolicyRequired {
		t.Fatalf("join: %s %v", policy, err)
	}
	if p := f.pulls[0]; p.Procedure != "acme/group_keys_v1" || string(p.Token) != "grant" {
		t.Fatalf("pulled %q with token %q", p.Procedure, p.Token)
	}
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil || f.pullCount() != 1 {
		t.Fatalf("a second join pulled again (%d pulls, %v)", f.pullCount(), err)
	}
	if e, err := k.PublishEpoch(context.Background(), realm, prefix); err != nil || e.ID[0] != 1 || f.pullCount() != 1 {
		t.Fatalf("publish under the held epoch: %v %v, %d pulls", e.ID, err, f.pullCount())
	}
	if got, _, held := k.Policy(realm, prefix+"/room/said_v1"); !held || got != prefix {
		t.Fatalf("the topic under the group is not covered: %q %v", got, held)
	}
	if _, _, held := k.Policy(realm, "io.macula/acme/chatter/x"); held {
		t.Fatal("a sibling prefix is covered")
	}
}

func TestAJoinTheDistributorRefusesIsNamed(t *testing.T) {
	f := newFake()
	f.refuse = "not_a_member"
	_, err := f.keyring().Join(context.Background(), realm, prefix, JoinOptions{})
	if !errors.Is(err, &Error{Reason: ReasonNotAMember}) {
		t.Fatalf("join refused as %v", err)
	}
	f.refuse, f.failWith = "", errors.New("unreachable")
	_, err = f.keyring().Join(context.Background(), realm, prefix, JoinOptions{})
	if !errors.Is(err, &Error{Reason: ReasonNoDistributor}) {
		t.Fatalf("an unreachable distributor is %v", err)
	}
	if _, err := f.keyring().Join(context.Background(), realm, "io.macula", JoinOptions{}); !errors.Is(err, ErrInvalidGroup) {
		t.Fatalf("a prefix without an org: %v", err)
	}
}

func TestThePolicyIsMonotonic(t *testing.T) {
	f := newFake()
	k := f.keyring()
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil {
		t.Fatal(err)
	}
	f.policy = PolicyOff
	f.fire()
	if _, policy, _ := k.Policy(realm, prefix); policy != PolicyRequired {
		t.Fatalf("off after required was taken: %s", policy)
	}
}

func TestAHolderRepullsInTheAheadWindowAndBacksOff(t *testing.T) {
	f := newFake()
	k := f.keyring()
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil {
		t.Fatal(err)
	}
	// The re-pull lands halfway through the last third of the epoch.
	want := time.Duration(DefaultRotateAfterMs-DefaultRotateAfterMs/3+DefaultRotateAfterMs/6) * time.Millisecond
	if got := f.lastDelay(); got != want {
		t.Fatalf("re-pull in %v, want %v", got, want)
	}
	f.failWith = errors.New("withheld")
	f.fire()
	if got := f.lastDelay(); got != time.Second {
		t.Fatalf("first retry in %v", got)
	}
	f.fire()
	if got := f.lastDelay(); got != 2*time.Second {
		t.Fatalf("second retry in %v", got)
	}
	f.failWith = nil
	f.served = append(f.served, epochAt(2, 1_000_000+DefaultRotateAfterMs))
	f.fire()
	if _, err := k.OpenEpoch(context.Background(), realm, prefix, [IDSize]byte{2}, [32]byte{}); err != nil {
		t.Fatalf("the next epoch was not held after the re-pull: %v", err)
	}
}

func TestAPublisherPastItsEpochPullsAndFailsClosed(t *testing.T) {
	f := newFake()
	k := f.keyring()
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil {
		t.Fatal(err)
	}
	f.now += DefaultRotateAfterMs
	f.failWith = errors.New("withheld")
	if _, err := k.PublishEpoch(context.Background(), realm, prefix); !errors.Is(err, &Error{Reason: ReasonNoDistributor}) {
		t.Fatalf("publish past the epoch: %v", err)
	}
	f.failWith = nil
	f.served = []Epoch{epochAt(2, f.now)}
	if e, err := k.PublishEpoch(context.Background(), realm, prefix); err != nil || e.ID[0] != 2 {
		t.Fatalf("publish after the pull: %v %v", e.ID, err)
	}
}

func TestUnknownIDsAreBoundedAndRemembered(t *testing.T) {
	f := newFake()
	k := f.keyring()
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil {
		t.Fatal(err)
	}
	publisher := [32]byte{0x77}
	for i := byte(10); i < 13; i++ {
		if _, err := k.OpenEpoch(context.Background(), realm, prefix, [IDSize]byte{i}, publisher); !errors.Is(err, &Error{Reason: ReasonUnknownEpoch}) {
			t.Fatalf("unknown id %d: %v", i, err)
		}
	}
	pulls := f.pullCount()
	if _, err := k.OpenEpoch(context.Background(), realm, prefix, [IDSize]byte{13}, publisher); !errors.Is(err, &Error{Reason: ReasonUnknownEpoch}) || f.pullCount() != pulls {
		t.Fatalf("a fourth unknown id pulled (%d pulls, %v)", f.pullCount()-pulls, err)
	}
	if _, err := k.OpenEpoch(context.Background(), realm, prefix, [IDSize]byte{10}, [32]byte{0x78}); err == nil || f.pullCount() != pulls {
		t.Fatalf("a remembered unknown id pulled again (%d pulls, %v)", f.pullCount()-pulls, err)
	}
}

func TestAnEpochPastItsAcceptanceIsExpired(t *testing.T) {
	f := newFake()
	k := f.keyring()
	if _, err := k.Join(context.Background(), realm, prefix, JoinOptions{}); err != nil {
		t.Fatal(err)
	}
	f.now += DefaultRotateAfterMs + eventLifeMs + toleranceMs + 1
	if _, err := k.OpenEpoch(context.Background(), realm, prefix, [IDSize]byte{1}, [32]byte{}); !errors.Is(err, &Error{Reason: ReasonEpochExpired}) {
		t.Fatalf("an expired epoch opened: %v", err)
	}
}

func TestEventsSealAndOpenOnlyUnderTheirFields(t *testing.T) {
	e := epochAt(1, 0)
	fields := Fields{Realm: realm, Topic: prefix + "/said_v1", Publisher: [32]byte{9}, Seq: 4, PublishedAt: 5}
	payload := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("text"), Val: cbor.Text("hello")}})
	sealed, err := SealEvent(e, fields, payload)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenEvent(e, fields, sealed)
	if err != nil || !bytes.Equal(cbor.Encode(opened), cbor.Encode(payload)) {
		t.Fatalf("opened %v, %v", opened, err)
	}
	moved := fields
	moved.Topic = prefix + "/other_v1"
	if _, err := OpenEvent(e, moved, sealed); err != ErrTagInvalid {
		t.Fatalf("an event under another topic opened: %v", err)
	}
	if _, err := OpenEvent(epochAt(2, 0), fields, sealed); err != ErrTagInvalid {
		t.Fatalf("an event opened under another epoch: %v", err)
	}
}

// TestEventsBindMaculasAAD binds macula's sealed events
// (seal/testdata/e2e_seal_v1.json, events) to the AAD macula computed for
// their routing fields. Their plaintexts are random bytes rather than a
// payload, so opening one end to end is the interop's (scripts/interop).
func TestEventsBindMaculasAAD(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "seal", "testdata", "e2e_seal_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Events []struct {
			Realm       string `json:"realm"`
			Topic       string `json:"topic"`
			Publisher   string `json:"publisher"`
			Seq         uint64 `json:"seq"`
			PublishedAt uint64 `json:"published_at"`
			Aad         string `json:"aad"`
		} `json:"events"`
	}
	if err := json.Unmarshal(raw, &v); err != nil || len(v.Events) == 0 {
		t.Fatalf("%d events, %v", len(v.Events), err)
	}
	for _, ev := range v.Events {
		f := Fields{Realm: [32]byte(unhex(t, ev.Realm)), Topic: ev.Topic, Publisher: [32]byte(unhex(t, ev.Publisher)),
			Seq: ev.Seq, PublishedAt: ev.PublishedAt}
		if got := aad(f); !bytes.Equal(got, unhex(t, ev.Aad)) {
			t.Fatalf("aad %x, macula's %s", got, ev.Aad)
		}
	}
}
