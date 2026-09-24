package pool

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/internal/teststation"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
)

const (
	org       = "mcl-echo"
	procedure = "mcl-echo/echo"
	topic     = "mcl-news/wire/news_item_reported_v1"
)

func seedOf(s *teststation.Station) Seed {
	return Seed{Host: s.Host, Port: s.Port, NodeID: s.NodeID}
}

// connect is a pool of node name on seeds, trusting realm, closed when the test
// ends.
func connect(t *testing.T, name string, realm teststation.Realm, seeds ...*teststation.Station) *Pool {
	t.Helper()
	return connectWith(t, name, realm, func(*Opts) {}, seeds...)
}

func connectWith(t *testing.T, name string, realm teststation.Realm, shape func(*Opts), seeds ...*teststation.Station) *Pool {
	t.Helper()
	opts := Opts{IdentityKey: teststation.Key(t, profile.PQPure, name),
		RealmTrust: map[[32]byte][]byte{realm.ID: realm.RealmKey()}, RespawnDelay: 100 * time.Millisecond}
	shape(&opts)
	list := make([]Seed, len(seeds))
	for i, s := range seeds {
		list[i] = seedOf(s)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	p, err := Connect(ctx, list, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func echo(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("never: %s", what)
}

// Connect refuses, before dialing anything, a seed without the station's
// node_id, a realm key that is not a key of the pool's profile, and more seeds
// than MaxSeeds.
func TestConnectRefusesWhatCannotBeTrusted(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "refusals")
	key := teststation.Key(t, profile.PQPure, "refused")
	ctx := t.Context()
	unpinned := Seed{Host: s.Host, Port: s.Port}
	if _, err := Connect(ctx, []Seed{unpinned}, Opts{IdentityKey: key}); !errors.Is(err, ErrSeedNotPinned) {
		t.Errorf("an unpinned seed: %v, want ErrSeedNotPinned", err)
	}
	bad := map[[32]byte][]byte{{1}: []byte("not a key")}
	if _, err := Connect(ctx, []Seed{seedOf(s)}, Opts{IdentityKey: key, RealmTrust: bad}); !errors.Is(err, ErrRealmTrustInvalid) {
		t.Errorf("a malformed realm key: %v, want ErrRealmTrustInvalid", err)
	}
	many := make([]Seed, 3)
	for i := range many {
		many[i] = seedOf(s)
	}
	if _, err := Connect(ctx, many, Opts{IdentityKey: key, MaxSeeds: 2}); !errors.Is(err, ErrTooManySeeds) {
		t.Errorf("too many seeds: %v, want ErrTooManySeeds", err)
	}
	if _, err := Connect(ctx, nil, Opts{IdentityKey: key}); !errors.Is(err, ErrNoSeeds) {
		t.Errorf("no seeds: %v, want ErrNoSeeds", err)
	}
}

// A pool links to every seed as one node, and a link that drops is dialed
// again.
func TestAPoolLinksEverySeedAndRedialsADroppedOne(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "seed a")
	b := teststation.Start(t, profile.PQPure, "seed b")
	realm := teststation.NewRealm(t, profile.PQPure, "links", org)
	p := connect(t, "links", realm, a, b)
	eventually(t, "both links up", func() bool { return a.Connected(p.NodeID()) && b.Connected(p.NodeID()) })
	a.Drop(p.NodeID())
	eventually(t, "the dropped link redialed", func() bool { return a.Connected(p.NodeID()) })
	up := 0
	for _, l := range p.Status() {
		if l.Up {
			up++
		}
	}
	if up != 2 {
		t.Errorf("%d links up, want 2", up)
	}
}

// A subscription hears a publication once however many of the pool's links
// deliver it, and keeps hearing after its link is redialed.
func TestASubscriptionHearsOnceAndSurvivesARedial(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "pubsub a")
	b := teststation.Start(t, profile.PQPure, "pubsub b")
	realm := teststation.NewRealm(t, profile.PQPure, "pubsub", org)
	listener := connect(t, "listener", realm, a, b)
	publisher := connect(t, "publisher", realm, a, b)
	sub, err := listener.Subscribe(realm.ID, topic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	heard := func(text string) int {
		if err := publisher.Publish(stationlink.Publication{Realm: realm.ID, Topic: topic, Payload: cbor.Text(text)}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
		n := 0
		timeout := time.After(time.Second)
		for {
			select {
			case event := <-sub.Events():
				if got, _ := event.Payload.AsText(); got == text {
					n++
				}
			case <-timeout:
				return n
			}
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := heard("first"); n != 1 {
		t.Errorf("heard the first %d times, want once", n)
	}
	a.Drop(listener.NodeID())
	b.Drop(listener.NodeID())
	eventually(t, "the listener redialed", func() bool { return a.Connected(listener.NodeID()) && b.Connected(listener.NodeID()) })
	time.Sleep(200 * time.Millisecond)
	if n := heard("after"); n != 1 {
		t.Errorf("heard after the redial %d times, want once", n)
	}
}

// A caller reaches a provider it shares no station with: the pool resolves the
// procedure's advertisement from the DHT, checks it against the realm key,
// dials the serving station the advertisement names, and calls the provider
// there.
func TestACallDialsTheProvidersStation(t *testing.T) {
	serving := teststation.Start(t, profile.PQPure, "serving")
	callers := teststation.Start(t, profile.PQPure, "callers")
	teststation.ShareDHT(serving, callers)
	realm := teststation.NewRealm(t, profile.PQPure, "direct", org)
	providerID := nodeIDOf(t, "provider")
	realm.Admit(t, serving, providerID)
	provider := connect(t, "provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connect(t, "caller", realm, callers)
	result, err := caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello")})
	if text, _ := result.AsText(); err != nil || text != "hello" {
		t.Fatalf("Call: %q, %v", text, err)
	}
	if !serving.Connected(caller.NodeID()) {
		t.Error("the caller did not dial the serving station")
	}
	providers, err := caller.Providers(t.Context(), realm.ID, procedure)
	if err != nil || len(providers) != 1 || providers[0].Node != providerID || providers[0].Station != serving.NodeID {
		t.Errorf("Providers: %+v, %v", providers, err)
	}
}

// An advertisement the pinned realm key did not authorize is not trusted, and a
// realm with no pinned key is refused before the DHT is asked.
func TestACallTrustsOnlyThePinnedRealm(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "trust")
	realm := teststation.NewRealm(t, profile.PQPure, "trusted", org)
	impostor := teststation.NewRealm(t, profile.PQPure, "trusted", org)
	impostor.Key = teststation.Key(t, profile.PQPure, "impostor realm")
	providerID := nodeIDOf(t, "impostor provider")
	impostor.Admit(t, s, providerID)
	provider := connectWith(t, "impostor provider", impostor, func(o *Opts) {
		o.RealmTrust = map[[32]byte][]byte{impostor.ID: impostor.RealmKey()}
	}, s)
	if _, err := provider.Serve(t.Context(), Offer{Realm: impostor.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connect(t, "trusting caller", realm, s)
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := caller.Call(ctx, Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Map(nil)}); !errors.Is(err, ErrNoProvider) {
		t.Errorf("an untrusted provider: %v, want ErrNoProvider", err)
	}
	if _, err := caller.Call(ctx, Call{Realm: [32]byte{9}, Procedure: procedure, Payload: cbor.Map(nil)}); !errors.Is(err, ErrNoRealmKey) {
		t.Errorf("an unpinned realm: %v, want ErrNoRealmKey", err)
	}
}

// A provider's advertisement is back at its station after its link is
// redialed, and Stop withdraws it everywhere.
func TestAServedProcedureSurvivesARedialUntilStopped(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "replay")
	realm := teststation.NewRealm(t, profile.PQPure, "replay", org)
	realm.Admit(t, s, nodeIDOf(t, "replayed provider"))
	provider := connect(t, "replayed provider", realm, s)
	served, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo})
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	eventually(t, "advertised", func() bool { return s.Advertised(realm.ID, procedure) })
	s.Drop(provider.NodeID())
	eventually(t, "advertised again after the redial", func() bool {
		return s.Connected(provider.NodeID()) && s.Advertised(realm.ID, procedure)
	})
	if err := served.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	eventually(t, "withdrawn", func() bool { return !s.Advertised(realm.ID, procedure) })
}

// A procedure call goes to the next candidate when a provider's station cannot
// be reached, and a provider's own error comes back as it is.
func TestACallTriesTheNextCandidate(t *testing.T) {
	gone := teststation.Start(t, profile.PQPure, "gone")
	live := teststation.Start(t, profile.PQPure, "live")
	teststation.ShareDHT(gone, live)
	realm := teststation.NewRealm(t, profile.PQPure, "candidates", org)
	realm.Admit(t, gone, nodeIDOf(t, "lost provider"), nodeIDOf(t, "live provider"))
	refusing := func(context.Context, stationlink.Request) (cbor.Value, error) { return cbor.Value{}, errors.New("no") }
	liveProvider := connect(t, "live provider", realm, live)
	if _, err := liveProvider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: refusing}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// The lost provider advertises last, so its candidate is the freshest and
	// is tried first.
	lost := connect(t, "lost provider", realm, gone)
	if _, err := lost.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connect(t, "candidate caller", realm, live)
	providers, err := caller.Providers(t.Context(), realm.ID, procedure)
	if err != nil || len(providers) != 2 || providers[0].Node != nodeIDOf(t, "lost provider") {
		t.Fatalf("Providers, freshest first: %+v, %v", providers, err)
	}
	gone.Stop()
	_, err = caller.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Map(nil), Timeout: 5 * time.Second})
	var provided *stationlink.ProviderError
	if !errors.As(err, &provided) || provided.Code != "handler_error" {
		t.Errorf("Call: %v, want the live provider's handler_error", err)
	}
}

func nodeIDOf(t *testing.T, name string) [32]byte {
	t.Helper()
	id, err := teststation.Key(t, profile.PQPure, name).NodeID()
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	return id
}

// A station's endpoint is trusted only when the station signed it: an
// endpoint another key signed, as a lying station would answer, is refused.
func TestAStationEndpointMustBeTheStationsOwn(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "liar")
	victim := teststation.Start(t, profile.PQPure, "victim")
	realm := teststation.NewRealm(t, profile.PQPure, "endpoints", org)
	p := connect(t, "endpoint caller", realm, s)
	forged, err := record.NewStationEndpoint(s.Port, record.StationEndpointOptions{HostAdvertised: []string{s.Host}})
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	signed, err := record.Sign(forged, s.Key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	s.Forge(record.StationEndpointKey(victim.NodeID), wire)
	if _, err := p.endpointOf(t.Context(), victim.NodeID); !errors.Is(err, ErrNoStationEndpoint) {
		t.Errorf("an endpoint the liar signed for the victim: %v, want ErrNoStationEndpoint", err)
	}
	if target, err := p.endpointOf(t.Context(), s.NodeID); err != nil || target.ExpectedNodeID != s.NodeID {
		t.Errorf("the liar's own endpoint: %+v, %v", target, err)
	}
}

// A station dialed directly that is never reached is not kept: it holds no
// direct-link place and is not dialed again.
func TestAnUnreachedDirectStationIsNotKept(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "keeps")
	gone := teststation.Start(t, profile.PQPure, "never reached")
	teststation.ShareDHT(s, gone)
	gone.Stop()
	realm := teststation.NewRealm(t, profile.PQPure, "keeps", org)
	p := connect(t, "keeper", realm, s)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if _, err := p.linkTo(ctx, gone.NodeID); err == nil {
		t.Fatal("a stopped station was linked")
	}
	for _, l := range p.Status() {
		if l.Station == gone.NodeID {
			t.Errorf("the unreached station is still held: %+v", l)
		}
	}
}

// Unsubscribe ends a subscription on every link: its events close, and each
// station stops routing the topic to the node.
func TestUnsubscribeEndsTheSubscriptionEverywhere(t *testing.T) {
	a := teststation.Start(t, profile.PQPure, "unsubscribe a")
	b := teststation.Start(t, profile.PQPure, "unsubscribe b")
	realm := teststation.NewRealm(t, profile.PQPure, "unsubscribe", org)
	p := connect(t, "unsubscriber", realm, a, b)
	eventually(t, "both links up", func() bool { return a.Connected(p.NodeID()) && b.Connected(p.NodeID()) })
	sub, err := p.Subscribe(realm.ID, topic)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	eventually(t, "subscribed at both stations", func() bool {
		return a.Subscribed(p.NodeID(), realm.ID, topic) && b.Subscribed(p.NodeID(), realm.ID, topic)
	})
	if err := sub.Unsubscribe(); err != nil {
		t.Fatalf("Unsubscribe: %v", err)
	}
	if _, open := <-sub.Events(); open {
		t.Error("the subscription's events are still open")
	}
	eventually(t, "unsubscribed at both stations", func() bool {
		return !a.Subscribed(p.NodeID(), realm.ID, topic) && !b.Subscribed(p.NodeID(), realm.ID, topic)
	})
}

// A record put through the pool is found by its type through the pool,
// verified.
func TestARecordPutThroughThePoolIsFoundByType(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "records")
	realm := teststation.NewRealm(t, profile.PQPure, "records", org)
	p := connect(t, "recorder", realm, s)
	unsigned, err := record.NewNodeRecord(p.NodeID(), nil, 0, record.NodeRecordOptions{DisplayName: "recorder"})
	if err != nil {
		t.Fatalf("node record: %v", err)
	}
	signed, err := record.Sign(unsigned, teststation.Key(t, profile.PQPure, "recorder"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := p.PutRecord(t.Context(), wire); err != nil {
		t.Fatalf("PutRecord: %v", err)
	}
	found, dropped, err := p.FindRecordsByType(t.Context(), record.TypeNodeRecord)
	if err != nil || dropped != 0 || len(found) != 1 || found[0].Record().KeyID != p.NodeID() {
		t.Errorf("FindRecordsByType: %d found, %d dropped, %v", len(found), dropped, err)
	}
}

// A streaming procedure is served on the pool's links and opened by direct
// dial from a node that shares no station with its provider.
func TestAStreamDialsTheProvidersStation(t *testing.T) {
	serving := teststation.Start(t, profile.PQPure, "stream serving")
	callers := teststation.Start(t, profile.PQPure, "stream callers")
	teststation.ShareDHT(serving, callers)
	realm := teststation.NewRealm(t, profile.PQPure, "streams", org)
	realm.Admit(t, serving, nodeIDOf(t, "stream provider"))
	provider := connect(t, "stream provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			for _, chunk := range []string{"a", "b"} {
				if err := s.Send([]byte(chunk)); err != nil {
					return err
				}
			}
			return s.Close()
		}}}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	caller := connect(t, "stream caller", realm, callers)
	stream, err := caller.OpenStream(t.Context(), StreamCall{Realm: realm.ID, Procedure: procedure, Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	var got []string
	for {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		event, err := stream.Recv(ctx)
		cancel()
		if err != nil {
			t.Fatalf("Recv: %v", err)
		}
		if event.Kind == stationlink.StreamEnd {
			break
		}
		body, _ := event.Body.AsBytes()
		got = append(got, string(body))
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("heard %v", got)
	}
	eventually(t, "every relayed stream released", func() bool { return serving.Relayed() == 0 })
}
