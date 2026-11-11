package pool

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
)

// unserved is a caller on a station whose DHT holds no advertisement of
// procedure, shaped by shape.
func unserved(t *testing.T, name string, shape func(*Opts)) (*Pool, teststation.Realm) {
	t.Helper()
	s := teststation.Start(t, profile.PQPure, name)
	realm := teststation.NewRealm(t, profile.PQPure, name, org)
	return connectWith(t, name+" caller", realm, shape, s), realm
}

// endpointWire is station's own endpoint record as a station_endpoint record
// naming port, signed by the station, so that a caller dials whatever address
// the test publishes for it.
func endpointWire(t *testing.T, station *teststation.Station, port uint16) []byte {
	t.Helper()
	unsigned, err := record.NewStationEndpoint(port, record.StationEndpointOptions{HostAdvertised: []string{station.Host}})
	if err != nil {
		t.Fatalf("endpoint record: %v", err)
	}
	signed, err := record.Sign(unsigned, station.Key)
	if err != nil {
		t.Fatalf("sign the endpoint: %v", err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		t.Fatalf("encode the endpoint: %v", err)
	}
	return wire
}

// A procedure nobody advertises is answered with the bare ErrNoProvider, at the
// end of the call's deadline and not before it: a miss is not final until the
// deadline (macula-go#76).
func TestAProcedureNobodyServesIsNoProviderAtTheDeadline(t *testing.T) {
	caller, realm := unserved(t, "reask nobody", func(*Opts) {})
	start := time.Now()
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 300 * time.Millisecond})
	took := time.Since(start)
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("Call: %v, want ErrNoProvider", err)
	}
	if took < 250*time.Millisecond {
		t.Errorf("the call gave up after %s, want the full 300ms deadline", took)
	}
}

// At the deadline a candidate that was never reached outranks everything else,
// and is joined with ErrNoProvider so that a binding still reads no_provider
// (macula_direct_dial.erl:61-67).
func TestADeadlineCandidateFailureIsNoProvider(t *testing.T) {
	serving, dht := teststation.Start(t, profile.PQPure, "order a serving"), teststation.Start(t, profile.PQPure, "order a dht")
	teststation.ShareDHT(serving, dht)
	realm := teststation.NewRealm(t, profile.PQPure, "order a", org)
	realm.Admit(t, serving, nodeIDOf(t, "order a provider"))
	provider := connect(t, "order a provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	refuser := teststation.Start(t, profile.PQPure, "order a refuser")
	refuser.Refuse(10 * time.Second)
	serving.Put(endpointWire(t, serving, refuser.Port))
	caller := connect(t, "order a caller", realm, dht)
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 600 * time.Millisecond})
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("Call: %v, want a failure joined with ErrNoProvider", err)
	}
	if !contains(err, "provider ") {
		t.Errorf("Call: %v, want the candidate's own failure in the error", err)
	}
}

// A lookup that found nothing concludes with the bare ErrNoProvider, not a
// wrapper: pullGroupKey tells "not advertised" from "unreachable" by identity
// (pool/group.go:74).
func TestADeadlineEmptyLookupIsTheBareSentinel(t *testing.T) {
	caller, realm := unserved(t, "order b", func(*Opts) {})
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 300 * time.Millisecond})
	if err != ErrNoProvider {
		t.Errorf("Call: %v, want the bare ErrNoProvider, which pullGroupKey compares by identity", err)
	}
}

// A lookup that failed concludes with that failure joined with the call's own
// deadline, so it reads the same under an unbounded context and a bounded one.
func TestADeadlineFailedLookupCarriesTheDeadline(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "order c")
	realm := teststation.NewRealm(t, profile.PQPure, "order c", org)
	caller := connect(t, "order c caller", realm, s)
	// A station that is gone cannot answer the lookup at all: each round's read
	// fails with ErrNoLink, which is the latest failed lookup.
	s.Stop()
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 500 * time.Millisecond})
	if !errors.Is(err, ErrNoLink) || !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Call: %v, want the failed lookup joined with the deadline", err)
	}
	if errors.Is(err, ErrNoProvider) {
		t.Errorf("Call: %v, want no conclusion in a failed lookup's error", err)
	}
}

// With nothing else to report, the deadline is the error: a lookup the deadline
// cut off records nothing (macula_direct_dial.erl:61-67).
func TestADeadlineAloneIsTheTimeout(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "order d")
	realm := teststation.NewRealm(t, profile.PQPure, "order d", org)
	caller := connect(t, "order d caller", realm, s)
	s.Silence(caller.NodeID(), time.Minute)
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 300 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrNoProvider) {
		t.Errorf("Call: %v, want the call's own deadline and no conclusion", err)
	}
}

// A call that is cancelled reports the cancellation, and carries no
// no-provider: the conclusion is not something a cancel is allowed to claim.
func TestACancelledCallStaysCancelled(t *testing.T) {
	caller, realm := unserved(t, "reask cancel", func(*Opts) {})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := caller.Call(ctx, Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 3 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Call: %v, want context.Canceled", err)
	}
	if errors.Is(err, ErrNoProvider) {
		t.Errorf("Call: %v, want no no-provider in a cancelled call's error", err)
	}
}

// An unserved stream gives up inside the dial window, not at the stream's own
// deadline: how long a stream may live is not how long its resolve may take
// (macula's ?DEFAULT_DIAL_TIMEOUT_MS, macula_direct_dial.erl:184).
func TestAnUnservedStreamGivesUpInsideTheDialWindow(t *testing.T) {
	window := 300 * time.Millisecond
	caller, realm := unserved(t, "reask stream window", func(o *Opts) { o.DialTimeout = window })
	start := time.Now()
	_, err := caller.OpenStream(t.Context(), StreamCall{Realm: realm.ID, Procedure: procedure,
		Mode: frame.ServerStream, Payload: cbor.Text("x"), Deadline: 10 * time.Second})
	took := time.Since(start)
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("OpenStream: %v, want ErrNoProvider", err)
	}
	// The bound is the window the caller set, not a number of our own: the phase
	// re-asks until it, and nothing runs it for ten times as long.
	if took > 3*window {
		t.Errorf("OpenStream gave up after %s, want inside its %s dial window, not the stream's 10s deadline", took, window)
	}
	if took < window/2 {
		t.Errorf("OpenStream gave up after %s, want the phase to keep asking until its %s window", took, window)
	}
}

// A stream whose advertisement arrives while the caller is still asking the DHT
// is opened: the phase re-asks, where one lookup used to end it.
func TestAStreamWhoseAdvertisementArrivesDuringThePhaseIsOpened(t *testing.T) {
	serving, dht := teststation.Start(t, profile.PQPure, "reask stream arriving serving"),
		teststation.Start(t, profile.PQPure, "reask stream arriving dht")
	teststation.ShareDHT(serving, dht)
	realm := teststation.NewRealm(t, profile.PQPure, "reask stream arriving", org)
	realm.Admit(t, serving, nodeIDOf(t, "reask stream arriving provider"))
	provider := connect(t, "reask stream arriving provider", realm, serving)
	caller := connectWith(t, "reask stream arriving caller", realm, func(o *Opts) { o.DialTimeout = 3 * time.Second }, dht)
	go func() {
		time.Sleep(200 * time.Millisecond)
		if _, err := provider.Serve(context.Background(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure,
			Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
				return s.Close()
			}}}); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	stream, err := caller.OpenStream(t.Context(), StreamCall{Realm: realm.ID, Procedure: procedure,
		Mode: frame.ServerStream, Payload: cbor.Text("x"), Deadline: time.Minute})
	if err != nil {
		t.Fatalf("OpenStream: %v, want the stream opened once the advertisement arrived", err)
	}
	_ = stream.Close()
}

// The resolve phase never shortens the STREAM_OPEN's signed deadline: the
// provider is told the deadline the caller asked for, not the phase's.
func TestThePhaseDoesNotShortenTheStreamsSignedDeadline(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "reask signed deadline")
	realm := teststation.NewRealm(t, profile.PQPure, "reask signed deadline", org)
	realm.Admit(t, s, nodeIDOf(t, "reask signed deadline provider"))
	served := make(chan uint64, 1)
	provider := connect(t, "reask signed deadline provider", realm, s)
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, str *stationlink.Stream) error {
			served <- str.Request().Deadline
			return str.Close()
		}}}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connectWith(t, "reask signed deadline caller", realm, func(o *Opts) { o.DialTimeout = 200 * time.Millisecond }, s)
	stream, err := caller.OpenStream(t.Context(), StreamCall{Realm: realm.ID, Procedure: procedure,
		Mode: frame.ServerStream, Payload: cbor.Text("x"), Deadline: 30 * time.Second})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer func() { _ = stream.Close() }()
	select {
	case deadlineMs := <-served:
		want := time.Now().Add(25 * time.Second).UnixMilli()
		if int64(deadlineMs) < want {
			t.Errorf("the provider was told deadline %d, want the caller's 30s one (at least %d), not the 200ms phase",
				deadlineMs, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the provider never saw the stream")
	}
}

// A station that moves its address during the call is dialled again: the
// endpoint record's identity changed, which is what makes it worth another
// attempt (macula_direct_dial.erl:56-59).
func TestAStationThatMovesItsAddressIsDialledAgain(t *testing.T) {
	serving, dht := teststation.Start(t, profile.PQPure, "reask moves serving"), teststation.Start(t, profile.PQPure, "reask moves dht")
	teststation.ShareDHT(serving, dht)
	realm := teststation.NewRealm(t, profile.PQPure, "reask moves", org)
	realm.Admit(t, serving, nodeIDOf(t, "reask moves provider"))
	provider := connect(t, "reask moves provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// The station's endpoint names a station that refuses connections, then the
	// real one: a dial that fails without waiting out the call's deadline.
	refuser := teststation.Start(t, profile.PQPure, "reask moves refuser")
	refuser.Refuse(10 * time.Second)
	serving.Put(endpointWire(t, serving, refuser.Port))
	caller := connect(t, "reask moves caller", realm, dht)
	moved := endpointWire(t, serving, serving.Port)
	go func() {
		time.Sleep(250 * time.Millisecond)
		serving.Put(moved)
	}()
	result, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("moved"),
		Timeout: 5 * time.Second})
	text, _ := result.AsText()
	if err != nil || text != "moved" {
		t.Errorf("Call: %q, %v, want the answer once the station moved", text, err)
	}
}

// The pause between rounds doubles from 100 ms to 1 s, macula's schedule
// (macula_direct_dial.erl:56-59), then stays there.
func TestTheResolveScheduleDoublesToTheCap(t *testing.T) {
	caller, realm := unserved(t, "reask schedule", func(*Opts) {})
	var pauses []time.Duration
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	restore := pauseFor
	pauseFor = func(context.Context, time.Duration) {}
	defer func() { pauseFor = restore }()
	pauseFor = func(_ context.Context, d time.Duration) {
		pauses = append(pauses, d)
		if len(pauses) == 6 {
			cancel()
		}
	}
	_, err := caller.Call(ctx, Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 30 * time.Second})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Call: %v, want the cancel that ended the schedule", err)
	}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond,
		800 * time.Millisecond, time.Second, time.Second}
	if len(pauses) < len(want) {
		t.Fatalf("%d pauses %v, want at least %v", len(pauses), pauses, want)
	}
	for i := range want {
		if pauses[i] != want[i] {
			t.Fatalf("pauses %v, want %v", pauses[:len(want)], want)
		}
	}
}

// The flake TestAStationDialledForACallIsPublic races: the first lookup lands on
// a fallback that does not hold the record, and that answer used to be final.
// Here the public station refuses connections until the call is under way, so
// the first lookup is certainly the fallback's, and the call still succeeds.
func TestACallSurvivesAFirstLookupOnAFallbackWithoutTheRecord(t *testing.T) {
	serving, public := teststation.Start(t, profile.PQPure, "reask flake serving"), teststation.Start(t, profile.PQPure, "reask flake public")
	fallback := teststation.Start(t, profile.PQPure, "reask flake fallback")
	teststation.ShareDHT(serving, public)
	realm := teststation.NewRealm(t, profile.PQPure, "reask flake", org)
	realm.Admit(t, serving, nodeIDOf(t, "reask flake provider"))
	provider := connect(t, "reask flake provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	public.Refuse(5 * time.Second)
	caller := connectTieredWith(t, "reask flake caller", realm, []*teststation.Station{public},
		[]*teststation.Station{fallback}, func(o *Opts) {
			o.Redial = Redial{Base: 100 * time.Millisecond, Factor: 2, Cap: time.Second, SteadyUp: time.Second}
		})
	if caller.linkedTo(public.NodeID) != nil {
		t.Fatal("the public station came up before the call; the fallback must answer the first lookup")
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		public.Allow()
	}()
	result, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello"),
		Timeout: 6 * time.Second})
	text, _ := result.AsText()
	if err != nil || text != "hello" {
		t.Errorf("Call: %q, %v, want the answer once the public tier came up", text, err)
	}
}

// A CALL that has gone out is never sent again, however many rounds the DHT is
// asked: the re-ask is of the DHT, never of a provider (macula-go#74).
func TestAProviderCalledOnceSeesOneCall(t *testing.T) {
	var entered atomic.Int32
	caller, realm := twoStationProviders(t, "reask once", Offer{Policy: ucan.Open{}, Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) {
		entered.Add(1)
		return r.Payload, nil
	}})
	result, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello"),
		Timeout: 3 * time.Second})
	text, _ := result.AsText()
	if err != nil || text != "hello" {
		t.Fatalf("Call: %q, %v", text, err)
	}
	if n := entered.Load(); n != 1 {
		t.Errorf("the handler was entered %d times, want once", n)
	}
}

// A station that is merely still down is not looked up again every round: only
// a changed advertisement or a changed station_endpoint record is worth another
// attempt (macula_direct_dial.erl:56-59).
func TestOnlyChangedCandidatesAreTriedAgain(t *testing.T) {
	serving, dht := teststation.Start(t, profile.PQPure, "reask unchanged serving"), teststation.Start(t, profile.PQPure, "reask unchanged dht")
	teststation.ShareDHT(serving, dht)
	realm := teststation.NewRealm(t, profile.PQPure, "reask unchanged", org)
	realm.Admit(t, serving, nodeIDOf(t, "reask unchanged provider"))
	provider := connect(t, "reask unchanged provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	refuser := teststation.Start(t, profile.PQPure, "reask unchanged refuser")
	refuser.Refuse(10 * time.Second)
	serving.Put(endpointWire(t, serving, refuser.Port))
	caller := connect(t, "reask unchanged caller", realm, dht)
	_, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("x"),
		Timeout: 900 * time.Millisecond})
	if !errors.Is(err, ErrNoProvider) {
		t.Fatalf("Call: %v, want the unreachable candidate's failure", err)
	}
	if dials := refuser.Arrivals(); dials != 1 {
		t.Errorf("the unchanged station was dialled %d times, want once: neither its advertisement nor its endpoint moved", dials)
	}
}

// contains reports whether err's text holds part, for the errors that carry a
// candidate's own failure as text rather than a sentinel.
func contains(err error, part string) bool {
	return err != nil && strings.Contains(err.Error(), part)
}

// The schedules are refused outside the bounds that make them schedules, and
// held to them at the edges: a factor of one keeps the pause at its floor, and a
// cap below the base is refused rather than silently grown.
func TestTheSchedulesRefuseWhatCannotBeOne(t *testing.T) {
	if _, err := (Resolve{Base: 2 * time.Second, Cap: time.Second}).checked(); !errors.Is(err, ErrInvalidOpts) {
		t.Errorf("a cap below the base: %v, want ErrInvalidOpts", err)
	}
	if _, err := (Resolve{Factor: -1}).checked(); !errors.Is(err, ErrInvalidOpts) {
		t.Errorf("a negative factor: %v, want ErrInvalidOpts", err)
	}
	at := Resolve{Base: time.Second, Factor: 1, Cap: time.Second}
	if got := at.next(at.Base); got != time.Second {
		t.Errorf("a factor of one from the base pauses %s, want %s", got, time.Second)
	}
	filled, err := (Resolve{}).checked()
	if err != nil || filled != (Resolve{Base: DefaultResolveBase, Factor: DefaultResolveFactor, Cap: DefaultResolveCap}) {
		t.Errorf("the zero schedule: %+v, %v, want macula's defaults", filled, err)
	}
	opts := Opts{DialTimeout: -time.Second}
	if err := checkSchedules(&opts); !errors.Is(err, ErrInvalidOpts) {
		t.Errorf("a negative dial timeout: %v, want ErrInvalidOpts", err)
	}
	opts = Opts{}
	if err := checkSchedules(&opts); err != nil || opts.DialTimeout != DefaultDialTimeout {
		t.Errorf("the zero dial timeout: %s, %v, want macula's default", opts.DialTimeout, err)
	}
}
