package pool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

// heldRecord is a signed node record of key, and the storage key it is found
// under: a record a station holds, put there directly so that a pool's
// procedures have something to answer with.
func heldRecord(t *testing.T, key *identity.NodeKey, name string) (wire []byte, storage [32]byte) {
	t.Helper()
	self, err := key.NodeID()
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	unsigned, err := record.NewNodeRecord(self, nil, 0, record.NodeRecordOptions{DisplayName: name})
	if err != nil {
		t.Fatalf("node record: %v", err)
	}
	signed, err := record.Sign(unsigned, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err = record.Encode(signed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	storage, err = record.StorageKey(signed)
	if err != nil {
		t.Fatalf("storage key: %v", err)
	}
	return wire, storage
}

// queried runs find on a pool in the background and reports how many records it
// answered with, or why it failed: a station procedure has no deadline of its
// own, so the test drives the drop while it waits.
func queried(t *testing.T, p *Pool, key [32]byte) <-chan queryResult {
	t.Helper()
	out := make(chan queryResult, 1)
	go func() {
		records, _, err := p.FindRecords(context.Background(), key)
		out <- queryResult{len(records), err}
	}()
	return out
}

type queryResult struct {
	found int
	err   error
}

// answered waits for a query's outcome, and for nothing longer than a station
// procedure's own timeout allows.
func answered(t *testing.T, out <-chan queryResult) queryResult {
	t.Helper()
	select {
	case got := <-out:
		return got
	case <-time.After(20 * time.Second):
		t.Fatal("the station procedure never returned")
		return queryResult{}
	}
}

// A station procedure in flight when its link ends is asked again on the
// pool's next link: a link that ends is a failure to reach the station, not
// the station's answer, and the station that ends may already have the
// request, which a retried read cannot make worse (macula-go#74).
func TestAStationQuerySurvivesALinkThatEndsMidRequest(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "link end a")
	b := teststation.Start(t, profile.PQPure, "link end b")
	realm := teststation.NewRealm(t, profile.PQPure, "link end", org)
	wire, key := heldRecord(t, teststation.Key(t, profile.PQPure, "link end record"), "held at b")
	b.Put(wire)
	p := connectWith(t, "link end caller", realm, func(*Opts) {}, a, b)
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	measuredRTT(t, map[[32]byte]time.Duration{a.NodeID: 5 * time.Millisecond, b.NodeID: 90 * time.Millisecond})
	a.Silence(p.NodeID(), 30*time.Second)
	out := queried(t, p, key)
	time.Sleep(200 * time.Millisecond)
	a.Drop(p.NodeID())
	if got := answered(t, out); got.err != nil || got.found != 1 {
		t.Errorf("the query answered %d records, %v, want the one station b holds", got.found, got.err)
	}
}

// A station procedure whose first link ends continues on the fallback once no
// public link is left: the walk follows the active tier as it stands, and the
// fallback is the active tier the moment the last public link ends
// (macula-go#74, macula#201 section 2).
func TestAStationQueryContinuesOnTheFallbackWhenTheLastPublicLinkEnds(t *testing.T) {
	public, fallback, realm := tiers(t)
	wire, key := heldRecord(t, teststation.Key(t, profile.PQPure, "fallback held record"), "held at the fallback")
	fallback.Put(wire)
	p := connectTiered(t, "tier walk", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	public.Silence(p.NodeID(), 30*time.Second)
	out := queried(t, p, key)
	time.Sleep(200 * time.Millisecond)
	public.Drop(p.NodeID())
	if got := answered(t, out); got.err != nil || got.found != 1 {
		t.Errorf("the query answered %d records, %v, want the record the fallback holds", got.found, got.err)
	}
	if tier := p.ActiveTier(); tier != TierFallback {
		t.Errorf("the active tier is %v, want the fallback now that no public link is up", tier)
	}
}

// No answer within the call's deadline is retried too, and for one reason
// only: the procedures a pool walks its links for can be run twice without a
// second result, a read changing nothing.
func TestAStationQueryMovesOnWhenNoAnswerComesInTime(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "quiet a")
	b := teststation.Start(t, profile.PQPure, "quiet b")
	realm := teststation.NewRealm(t, profile.PQPure, "quiet", org)
	wire, key := heldRecord(t, teststation.Key(t, profile.PQPure, "quiet record"), "held at b")
	b.Put(wire)
	p := connectWith(t, "quiet caller", realm, func(*Opts) {}, a, b)
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	measuredRTT(t, map[[32]byte]time.Duration{a.NodeID: 5 * time.Millisecond, b.NodeID: 90 * time.Millisecond})
	a.Silence(p.NodeID(), 30*time.Second)
	if got := answered(t, queried(t, p, key)); got.err != nil || got.found != 1 {
		t.Errorf("the query answered %d records, %v, want the one station b holds", got.found, got.err)
	}
}

// A station's own answer ends the operation, not_found included: the station
// that answered is not asked again and no other station answers in its place.
// A retry there would give a different result than the first station did,
// which is the one thing a retry must never do (macula-go#74).
func TestAStationAnswerIsFinalAndIsNotAskedAgain(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "final a")
	b := teststation.Start(t, profile.PQPure, "final b")
	realm := teststation.NewRealm(t, profile.PQPure, "final answer", org)
	wire, key := heldRecord(t, teststation.Key(t, profile.PQPure, "final record"), "held at b")
	b.Put(wire)
	p := connectWith(t, "final caller", realm, func(*Opts) {}, a, b)
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	measuredRTT(t, map[[32]byte]time.Duration{a.NodeID: 5 * time.Millisecond, b.NodeID: 90 * time.Millisecond})
	if _, err := p.FindRecord(t.Context(), key); !errors.Is(err, stationlink.ErrRecordNotFound) {
		t.Errorf("FindRecord: %v, want the first station's not_found", err)
	}
	if n := a.Asked(p.NodeID(), stationlink.ProcedureFindRecord); n != 1 {
		t.Errorf("the station that answered was asked %d times, want once", n)
	}
	if n := b.Asked(p.NodeID(), stationlink.ProcedureFindRecord); n != 0 {
		t.Errorf("the other station was asked %d times, want never", n)
	}
}

// A station that redials gets a new link, and an operation that has already
// asked it does not ask it again: the walk is keyed by the station, and no more
// stations are asked than the pool has (macula-go#74).
//
// a is asked first and drops mid-request; the operation moves to b, which
// holds it until a's link is up again and then drops too. No link is left and a
// has been asked already, so the operation ends rather than asking a twice.
func TestAFlappingStationIsAskedOnceInOneOperation(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "flap a")
	b := teststation.Start(t, profile.PQPure, "flap b")
	realm := teststation.NewRealm(t, profile.PQPure, "flapping", org)
	p := connectWith(t, "flap caller", realm, func(*Opts) {}, a, b)
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	measuredRTT(t, map[[32]byte]time.Duration{a.NodeID: 5 * time.Millisecond, b.NodeID: 90 * time.Millisecond})
	a.Silence(p.NodeID(), 30*time.Second)
	b.Silence(p.NodeID(), 30*time.Second)
	_, key := heldRecord(t, teststation.Key(t, profile.PQPure, "flap record"), "held nowhere")
	out := queried(t, p, key)
	time.Sleep(200 * time.Millisecond)
	a.Drop(p.NodeID())
	go func() {
		for !a.Connected(p.NodeID()) {
			time.Sleep(10 * time.Millisecond)
		}
		b.Drop(p.NodeID())
	}()
	got := answered(t, out)
	if got.err == nil {
		t.Errorf("the operation answered %d records, want the error of an operation no link carried", got.found)
	}
	if n := a.Asked(p.NodeID(), stationlink.ProcedureFindRecords); n != 0 {
		t.Errorf("the station that redialed was asked again and answered %d times, want never", n)
	}
}

// The procedures a failed link is retried for are a closed set, pinned by
// name: a second run of any other procedure could give a different result, so
// adding one is a decision a reviewer sees, not an addition (macula-go#74).
func TestTheProceduresAFailedLinkIsRetriedFor(t *testing.T) {
	want := []string{
		stationlink.ProcedureFindRecord,
		stationlink.ProcedureFindRecords,
		stationlink.ProcedureFindRecordsByType,
		stationlink.ProcedurePutRecord,
	}
	if len(retryable) != len(want) {
		t.Fatalf("the retried procedures are %d, want the %d this test names", len(retryable), len(want))
	}
	for _, name := range want {
		if !retryable[name] {
			t.Errorf("%s is not retried for a failed link, and the test says it is", name)
		}
	}
}

// Each retried operation asks its station for the procedure it says it does:
// the name a pool passes is the one the wire carries, so the closed set above
// and the calls that go out cannot disagree (macula-go#74).
func TestEachRetriedProcedureIsTheOneTheWireCarries(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "naming")
	realm := teststation.NewRealm(t, profile.PQPure, "naming", org)
	wire, key := heldRecord(t, teststation.Key(t, profile.PQPure, "naming record"), "held here")
	s.Put(wire)
	p := connectWith(t, "naming caller", realm, func(*Opts) {}, s)
	eventually(t, "the link up", func() bool { return upCount(p) == 1 })
	ran := map[string]func(){
		stationlink.ProcedurePutRecord:         func() { _ = p.PutRecord(t.Context(), wire) },
		stationlink.ProcedureFindRecord:        func() { _, _ = p.FindRecord(t.Context(), key) },
		stationlink.ProcedureFindRecords:       func() { _, _, _ = p.FindRecords(t.Context(), key) },
		stationlink.ProcedureFindRecordsByType: func() { _, _, _ = p.FindRecordsByType(t.Context(), record.TypeNodeRecord) },
	}
	before := make(map[string]int, len(ran))
	for name := range ran {
		before[name] = s.Asked(p.NodeID(), name)
	}
	for _, run := range ran {
		run()
	}
	for name := range ran {
		if got := s.Asked(p.NodeID(), name) - before[name]; got != 1 {
			t.Errorf("the station answered %s %d times, want once: the operation's name and its call disagree", name, got)
		}
	}
}

// The predicate retries a call the link did not carry and nothing else: not a
// station's answer, not the caller's own deadline, not a frame over the cap.
func TestOnlyWhatTheLinkDidNotCarryIsRetried(t *testing.T) {
	link := &stationlink.Link{}
	for _, err := range []error{
		stationlink.ErrRecordNotFound, &stationlink.RecordRefusedError{Reason: "too_old"},
		stationlink.ErrMalformedReply, stationlink.ErrReplyVersionUnsupported,
		stationlink.ErrFrameTooLarge, context.Canceled, context.DeadlineExceeded,
	} {
		if unreachable(link, err) {
			t.Errorf("%v was retried on the next link, want a station's answer or the caller's own failure", err)
		}
	}
	if !unreachable(link, stationlink.ErrCallTimeout) {
		t.Error("a call no reply answered in time was not retried, want it retried for the procedures retryable names")
	}
}
