package directdial

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/dht"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/stream"
)

// These tests drive resolution through the package's lookup and per-station
// variables, so no network is involved. They set package variables, so none
// of them runs in parallel.

var testRealm = make([]byte, 32)

const testProcedure = "candidates_test.echo_v1"

var (
	errUnreachable = errors.New("test: dial failed")
	okResponse     = frame.CallResponse{Payload: cbor.Text("ok")}
)

// fakeDHT answers FindRecords with successive replies per key, the last one
// repeating, and FindRecord with one record per key.
type fakeDHT struct {
	mu       sync.Mutex
	replies  map[[32]byte][][]dht.Record
	asked    map[[32]byte]int
	endpoint map[[32]byte]dht.Record
}

func newFakeDHT() *fakeDHT {
	return &fakeDHT{
		replies:  map[[32]byte][][]dht.Record{},
		asked:    map[[32]byte]int{},
		endpoint: map[[32]byte]dht.Record{},
	}
}

func (f *fakeDHT) findRecords(_ *connection.Session, _ identity.KeyPair, key [32]byte, _ time.Duration) ([]dht.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	asked := f.asked[key]
	f.asked[key]++
	replies := f.replies[key]
	if len(replies) == 0 {
		return nil, nil
	}
	return replies[min(asked, len(replies)-1)], nil
}

// lookups is how many times FindRecords was asked about key.
func (f *fakeDHT) lookups(key [32]byte) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked[key]
}

// setEndpoint makes rec s's endpoint record from now on.
func (f *fakeDHT) setEndpoint(s station, rec dht.Record) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endpoint[dht.StationEndpointKey(s.id.NodeID())] = rec
}

func (f *fakeDHT) findRecord(_ *connection.Session, _ identity.KeyPair, key [32]byte, _ time.Duration) (dht.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec, ok := f.endpoint[key]
	if !ok {
		return dht.Record{}, dht.ErrNotFound
	}
	return rec, nil
}

// install points the package's lookup variables at f for the rest of t.
func install(t *testing.T, f *fakeDHT) {
	t.Helper()
	oldRecords, oldRecord := findRecords, findRecord
	findRecords, findRecord = f.findRecords, f.findRecord
	t.Cleanup(func() { findRecords, findRecord = oldRecords, oldRecord })
}

// visits records, in order, the hosts a per-station variable was asked to reach.
type visits struct {
	mu    sync.Mutex
	hosts []string
}

func (v *visits) add(host string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.hosts = append(v.hosts, host)
}

func (v *visits) seen() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.hosts...)
}

func equalHosts(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

type callAnswer struct {
	resp frame.CallResponse
	sent bool
	err  error
}

// installCallAt answers callAt per host from answers, recording each host asked.
func installCallAt(t *testing.T, v *visits, answers map[string]callAnswer) {
	t.Helper()
	old := callAt
	callAt = func(_ context.Context, _ time.Time, host string, _ uint16, _ []byte, _ identity.KeyPair, _ string, _ []byte, _ cbor.Value, _ []byte) (frame.CallResponse, bool, error) {
		v.add(host)
		a, ok := answers[host]
		if !ok {
			return frame.CallResponse{}, false, errors.New("test: no station at " + host)
		}
		return a.resp, a.sent, a.err
	}
	t.Cleanup(func() { callAt = old })
}

type fetchAnswer struct {
	data []byte
	err  error
}

// installFetchAt answers fetchAt per host from answers, recording each host asked.
func installFetchAt(t *testing.T, v *visits, answers map[string]fetchAnswer) {
	t.Helper()
	old := fetchAt
	fetchAt = func(_, _ context.Context, host string, _ uint16, _ []byte, _ identity.KeyPair, _ manifest.Mcid) ([]byte, error) {
		v.add(host)
		a, ok := answers[host]
		if !ok {
			return nil, errors.New("test: no provider at " + host)
		}
		return a.data, a.err
	}
	t.Cleanup(func() { fetchAt = old })
}

// station is a test station: its identity and the host its endpoint record advertises.
type station struct {
	id   identity.KeyPair
	host string
}

func newStation(t *testing.T, host string) station {
	t.Helper()
	return station{id: mustIdentity(t), host: host}
}

func mustIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

// endpointRecord is s's own signed station_endpoint record.
func endpointRecord(t *testing.T, s station) dht.Record {
	t.Helper()
	version := make([]byte, 16)
	if _, err := rand.Read(version); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	now := time.Now()
	rec := dht.Record{
		Type:      dht.TypeStationEndpoint,
		Key:       s.id.NodeID(),
		Version:   version,
		CreatedAt: now.UnixMilli(),
		ExpiresAt: now.Add(time.Hour).UnixMilli(),
		Payload: cbor.Map([]cbor.MapEntry{
			{Key: cbor.Text("host_advertised"), Val: cbor.List([]cbor.Value{cbor.Bytes([]byte(s.host))})},
			{Key: cbor.Text("quic_port"), Val: cbor.Int(4433)},
		}),
	}
	return dht.Sign(rec, s.id)
}

func procedureKey() [32]byte {
	return dht.ProcedureKey(dht.DiscoveryURI(testRealm, testProcedure))
}

// advertisement is a signed procedure_advertisement from a fresh provider
// naming s as its serving station. An expired one's validity has ended.
func advertisement(t *testing.T, s station, expired bool) dht.Record {
	t.Helper()
	provider := mustIdentity(t)
	rec, err := dht.NewProcedureAdvertisement(provider.NodeID(), dht.DiscoveryURI(testRealm, testProcedure), s.id.NodeID(), time.Hour)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisement: %v", err)
	}
	if expired {
		rec.CreatedAt = time.Now().Add(-2 * time.Hour).UnixMilli()
		rec.ExpiresAt = time.Now().Add(-time.Hour).UnixMilli()
	}
	return dht.Sign(rec, provider)
}

func testMcid() manifest.Mcid {
	return manifest.BlockMcid([]byte("candidates test content"))
}

// announcement is s's signed content_announcement for mcid, reachable at s's host.
func announcement(t *testing.T, s station, mcid manifest.Mcid) dht.Record {
	t.Helper()
	rec, err := dht.NewContentAnnouncement(s.id.NodeID(), mcid[:], "quic://"+s.host+":4433", time.Hour)
	if err != nil {
		t.Fatalf("NewContentAnnouncement: %v", err)
	}
	return dht.Sign(rec, s.id)
}

// A station whose endpoint record can't be found is skipped for the next
// advertisement's station.
func TestCallTriesTheNextAdvertisementWhenAStationHasNoEndpoint(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{"b.test": {resp: okResponse, sent: true}})

	resp, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second)
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got, _ := resp.Payload.AsText(); got != "ok" {
		t.Fatalf("Call reply = %v, want the reply from b.test", resp.Payload)
	}
	if got := v.seen(); !equalHosts(got, "b.test") {
		t.Fatalf("stations reached = %v, want [b.test]", got)
	}
}

// When records come back but none qualifies, resolution asks again until one does.
func TestCallRetriesWhenNoAdvertisementQualifies(t *testing.T) {
	stale, fresh := newStation(t, "stale.test"), newStation(t, "fresh.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, stale, true)}, {advertisement(t, fresh, false)}}
	f.endpoint[dht.StationEndpointKey(fresh.id.NodeID())] = endpointRecord(t, fresh)
	install(t, f)
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{"fresh.test": {resp: okResponse, sent: true}})

	if _, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := v.seen(); !equalHosts(got, "fresh.test") {
		t.Fatalf("stations reached = %v, want [fresh.test]", got)
	}
}

// A station that can't be dialled is skipped for the next one, for Call and
// CallWithUCAN alike.
func TestCallTriesTheNextStationWhenADialFails(t *testing.T) {
	calls := map[string]func(id identity.KeyPair) (frame.CallResponse, error){
		"Call": func(id identity.KeyPair) (frame.CallResponse, error) {
			return Call(context.Background(), nil, id, testRealm, testProcedure, cbor.Null(), 3*time.Second)
		},
		"CallWithUCAN": func(id identity.KeyPair) (frame.CallResponse, error) {
			return CallWithUCAN(context.Background(), nil, id, testRealm, testProcedure, cbor.Null(), 3*time.Second, []byte("token"))
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			a, b := newStation(t, "a.test"), newStation(t, "b.test")
			f := newFakeDHT()
			f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
			f.endpoint[dht.StationEndpointKey(a.id.NodeID())] = endpointRecord(t, a)
			f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
			install(t, f)
			v := &visits{}
			installCallAt(t, v, map[string]callAnswer{
				"a.test": {err: errUnreachable},
				"b.test": {resp: okResponse, sent: true},
			})
			if _, err := call(mustIdentity(t)); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if got := v.seen(); !equalHosts(got, "a.test", "b.test") {
				t.Fatalf("stations reached = %v, want [a.test b.test]", got)
			}
		})
	}
}

// Once the CALL has gone out, its outcome stands: no other station receives it.
func TestCallNeverSendsTheRequestTwice(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
	f.endpoint[dht.StationEndpointKey(a.id.NodeID())] = endpointRecord(t, a)
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	v := &visits{}
	lost := errors.New("test: stream reset after the CALL went out")
	installCallAt(t, v, map[string]callAnswer{
		"a.test": {sent: true, err: lost},
		"b.test": {resp: okResponse, sent: true},
	})

	_, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second)
	if !errors.Is(err, lost) {
		t.Fatalf("Call error = %v, want a.test's error", err)
	}
	if got := v.seen(); !equalHosts(got, "a.test") {
		t.Fatalf("stations reached = %v, want [a.test]", got)
	}
}

// The timeout bounds resolution, not only the dial and the request.
func TestCallTimeoutBoundsResolution(t *testing.T) {
	install(t, newFakeDHT())
	installCallAt(t, &visits{}, nil)

	start := time.Now()
	_, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Call returned after %v, want within its 300 ms timeout", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call error = %v, want one wrapping context.DeadlineExceeded", err)
	}
}

// The timeout bounds the lookup of a station's endpoint.
func TestCallTimeoutBoundsTheEndpointLookup(t *testing.T) {
	a := newStation(t, "a.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false)}}
	install(t, f)
	installCallAt(t, &visits{}, nil)

	start := time.Now()
	_, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Call returned after %v, want within its 300 ms timeout", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call error = %v, want one wrapping context.DeadlineExceeded", err)
	}
}

// A station that can't be dialled is skipped for the next one when opening a stream.
func TestOpenStreamDirectTriesTheNextStationWhenADialFails(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
	f.endpoint[dht.StationEndpointKey(a.id.NodeID())] = endpointRecord(t, a)
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	v := installOpenAt(t, map[string]bool{"b.test": true}, nil)

	_, h, err := OpenStreamDirect(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, frame.ServerStream, cbor.Null(), time.Now().Add(time.Minute).UnixMilli(), 3*time.Second)
	if err != nil || h == nil {
		t.Fatalf("OpenStreamDirect = (%v, %v), want a stream at b.test", h, err)
	}
	if got := v.seen(); !equalHosts(got, "a.test", "b.test") {
		t.Fatalf("stations reached = %v, want [a.test b.test]", got)
	}
}

// A stream whose opening frame may have gone out is not opened again elsewhere.
func TestOpenStreamDirectNeverOpensTheStreamTwice(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
	f.endpoint[dht.StationEndpointKey(a.id.NodeID())] = endpointRecord(t, a)
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	refused := errors.New("test: stream refused after its opening frame went out")
	v := installOpenAt(t, map[string]bool{"b.test": true}, map[string]error{"a.test": refused})

	_, _, err := OpenStreamDirect(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, frame.ServerStream, cbor.Null(), time.Now().Add(time.Minute).UnixMilli(), 3*time.Second)
	if !errors.Is(err, refused) {
		t.Fatalf("OpenStreamDirect error = %v, want a.test's error", err)
	}
	if got := v.seen(); !equalHosts(got, "a.test") {
		t.Fatalf("stations reached = %v, want [a.test]", got)
	}
}

// installOpenAt opens a stream at every host in opens, fails after sending at
// every host in refusals, and fails the dial everywhere else.
func installOpenAt(t *testing.T, opens map[string]bool, refusals map[string]error) *visits {
	t.Helper()
	v := &visits{}
	old := openAt
	openAt = func(_, _ context.Context, host string, _ uint16, _ []byte, _ identity.KeyPair, _ string, _ []byte, _ frame.StreamMode, _ cbor.Value, _ int64) (*connection.Session, *stream.Handle, bool, error) {
		v.add(host)
		if err, ok := refusals[host]; ok {
			return nil, nil, true, err
		}
		if opens[host] {
			return &connection.Session{}, &stream.Handle{}, true, nil
		}
		return nil, nil, false, errUnreachable
	}
	t.Cleanup(func() { openAt = old })
	return v
}

// When no provider has announced the content yet, GetDirect asks again until one has.
func TestGetDirectRetriesWhenNoProviderQualifies(t *testing.T) {
	p := newStation(t, "p.test")
	mcid := testMcid()
	f := newFakeDHT()
	f.replies[dht.ContentKey(mcid[:])] = [][]dht.Record{{}, {announcement(t, p, mcid)}}
	install(t, f)
	v := &visits{}
	installFetchAt(t, v, map[string]fetchAnswer{"p.test": {data: []byte("content")}})

	data, err := GetDirect(context.Background(), nil, mustIdentity(t), mcid, 3*time.Second)
	if err != nil || string(data) != "content" {
		t.Fatalf("GetDirect = (%q, %v), want the content from p.test", data, err)
	}
}

// A provider whose transfer fails, or whose bytes don't match the MCID, is
// skipped for the next provider: a fetch is verified, so trying again is safe.
func TestGetDirectTriesTheNextProviderAfterAFailedFetch(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	mcid := testMcid()
	f := newFakeDHT()
	f.replies[dht.ContentKey(mcid[:])] = [][]dht.Record{{announcement(t, a, mcid), announcement(t, b, mcid)}}
	install(t, f)
	v := &visits{}
	installFetchAt(t, v, map[string]fetchAnswer{
		"a.test": {err: errors.New("test: content failed verification")},
		"b.test": {data: []byte("content")},
	})

	data, err := GetDirect(context.Background(), nil, mustIdentity(t), mcid, 3*time.Second)
	if err != nil || string(data) != "content" {
		t.Fatalf("GetDirect = (%q, %v), want the content from b.test", data, err)
	}
	if got := v.seen(); !equalHosts(got, "a.test", "b.test") {
		t.Fatalf("providers reached = %v, want [a.test b.test]", got)
	}
}

// GetDirect's timeout bounds the search for a provider.
func TestGetDirectTimeoutBoundsResolution(t *testing.T) {
	install(t, newFakeDHT())
	installFetchAt(t, &visits{}, nil)

	start := time.Now()
	_, err := GetDirect(context.Background(), nil, mustIdentity(t), testMcid(), 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("GetDirect returned after %v, want within its 300 ms timeout", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("GetDirect error = %v, want one wrapping context.DeadlineExceeded", err)
	}
}

// PutDirect's timeout bounds the lookup of the station's endpoint.
func TestPutDirectTimeoutBoundsTheEndpointLookup(t *testing.T) {
	install(t, newFakeDHT())
	s := newStation(t, "s.test")

	start := time.Now()
	_, err := PutDirect(context.Background(), nil, mustIdentity(t), s.id.NodeID(), []byte("content"), "content.txt", 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("PutDirect returned after %v, want within its 300 ms timeout", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("PutDirect error = %v, want one wrapping context.DeadlineExceeded", err)
	}
}

// authorizedAdvertisement is advertisement with a cert chain: the provider's
// leaf certificate, issued by the realm CA for org.
func authorizedAdvertisement(t *testing.T, s station, caCert *x509.Certificate, caPriv ed25519.PrivateKey, org string) dht.Record {
	t.Helper()
	provider := mustIdentity(t)
	leafPEM := testLeafFor(t, caCert, caPriv, ed25519.PublicKey(provider.NodeID()), org)
	rec, err := dht.NewProcedureAdvertisementWithCertChain(provider.NodeID(), dht.DiscoveryURI(testRealm, testProcedure), s.id.NodeID(), time.Hour, leafPEM)
	if err != nil {
		t.Fatalf("NewProcedureAdvertisementWithCertChain: %v", err)
	}
	return dht.Sign(rec, provider)
}

// CallWithCertChain skips a station without an endpoint, just as Call does.
func TestCallWithCertChainTriesTheNextAdvertisementWhenAStationHasNoEndpoint(t *testing.T) {
	caPEM, caCert, caPriv := testRealmCA(t)
	const org = "candidates-test-org"
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{authorizedAdvertisement(t, a, caCert, caPriv, org), authorizedAdvertisement(t, b, caCert, caPriv, org)}}
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{"b.test": {resp: okResponse, sent: true}})

	if _, err := CallWithCertChain(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, caPEM, org, cbor.Null(), 3*time.Second); err != nil {
		t.Fatalf("CallWithCertChain: %v", err)
	}
	if got := v.seen(); !equalHosts(got, "b.test") {
		t.Fatalf("stations reached = %v, want [b.test]", got)
	}
}

// An advertisement authorized for another org keeps resolution asking until
// the deadline, and the error still says why nothing qualified.
func TestCallWithCertChainReportsTheAuthorizationFailureAtItsDeadline(t *testing.T) {
	caPEM, caCert, caPriv := testRealmCA(t)
	a := newStation(t, "a.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{authorizedAdvertisement(t, a, caCert, caPriv, "another-org")}}
	f.endpoint[dht.StationEndpointKey(a.id.NodeID())] = endpointRecord(t, a)
	install(t, f)
	v := &visits{}
	installCallAt(t, v, nil)

	start := time.Now()
	_, err := CallWithCertChain(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, caPEM, "candidates-test-org", cbor.Null(), 300*time.Millisecond)
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("CallWithCertChain returned after %v, want within its 300 ms timeout", elapsed)
	}
	if !errors.Is(err, ErrNoAuthorizedAdvertisement) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CallWithCertChain error = %v, want ErrNoAuthorizedAdvertisement wrapped with context.DeadlineExceeded", err)
	}
	if got := v.seen(); len(got) != 0 {
		t.Fatalf("stations reached = %v, want none", got)
	}
}

// Resolve settles on the first advertisement whose station endpoint resolves.
func TestResolveReturnsTheFirstStationWithAnEndpoint(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false), advertisement(t, b, false)}}
	f.endpoint[dht.StationEndpointKey(b.id.NodeID())] = endpointRecord(t, b)
	install(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	station, host, port, err := Resolve(ctx, nil, mustIdentity(t), testRealm, testProcedure)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !bytesEqual(station, b.id.NodeID()) || host != "b.test" || port != 4433 {
		t.Fatalf("Resolve = (%x, %s, %d), want b.test's station at port 4433", station, host, port)
	}
}

// ResolveStationEndpoint stops at its context's deadline.
func TestResolveStationEndpointStopsAtItsDeadline(t *testing.T) {
	install(t, newFakeDHT())
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, _, _, err := ResolveStationEndpoint(ctx, nil, mustIdentity(t), newStation(t, "s.test").id.NodeID())
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("ResolveStationEndpoint returned after %v, want within its 300 ms deadline", elapsed)
	}
	if !errors.Is(err, ErrStationEndpointNotFound) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ResolveStationEndpoint error = %v, want ErrStationEndpointNotFound wrapped with context.DeadlineExceeded", err)
	}
}

// A candidate's share is what remains split over the candidates not yet
// tried, never less than minCandidateShare while that much remains.
func TestCandidateShareSplitsTheRemainingTime(t *testing.T) {
	cases := []struct {
		remaining time.Duration
		untried   int
		atLeast   time.Duration
		atMost    time.Duration
	}{
		{remaining: 10 * time.Second, untried: 2, atLeast: 4900 * time.Millisecond, atMost: 5 * time.Second},
		{remaining: 10 * time.Second, untried: 100, atLeast: 990 * time.Millisecond, atMost: time.Second},
		{remaining: 300 * time.Millisecond, untried: 3, atLeast: 250 * time.Millisecond, atMost: 300 * time.Millisecond},
	}
	for _, c := range cases {
		ctx, cancel := context.WithTimeout(context.Background(), c.remaining)
		share := candidateShare(ctx, c.untried)
		cancel()
		if share < c.atLeast || share > c.atMost {
			t.Errorf("candidateShare(%v remaining, %d untried) = %v, want between %v and %v", c.remaining, c.untried, share, c.atLeast, c.atMost)
		}
	}
}

// A station that refuses at once is dialled once per version of its endpoint
// record, not again on every pass over the DHT.
func TestCallDialsARefusingStationOncePerEndpointVersion(t *testing.T) {
	a := newStation(t, "a.test")
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, a, false)}}
	f.setEndpoint(a, endpointRecord(t, a))
	install(t, f)
	republished := endpointRecord(t, a)
	time.AfterFunc(1500*time.Millisecond, func() { f.setEndpoint(a, republished) })
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{"a.test": {err: errUnreachable}})

	_, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second)
	if !errors.Is(err, errUnreachable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call error = %v, want the dial failure wrapped with context.DeadlineExceeded", err)
	}
	if got := v.seen(); !equalHosts(got, "a.test", "a.test") {
		t.Fatalf("dials = %v, want two: one for each version of a.test's endpoint record", got)
	}
}

// An advertisement that appears on a later pass is still tried, while the
// station that already refused, with nothing changed, is not dialled again.
func TestCallTriesAnAdvertisementThatAppearsOnALaterPass(t *testing.T) {
	a, b := newStation(t, "a.test"), newStation(t, "b.test")
	f := newFakeDHT()
	adA := advertisement(t, a, false)
	f.replies[procedureKey()] = [][]dht.Record{{adA}, {adA, advertisement(t, b, false)}}
	f.setEndpoint(a, endpointRecord(t, a))
	f.setEndpoint(b, endpointRecord(t, b))
	install(t, f)
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{
		"a.test": {err: errUnreachable},
		"b.test": {resp: okResponse, sent: true},
	})

	if _, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := v.seen(); !equalHosts(got, "a.test", "b.test") {
		t.Fatalf("dials = %v, want [a.test b.test]", got)
	}
}

// Passes over the DHT back off, doubling from 100 ms to at most 1 s.
func TestResolutionBacksOffBetweenPasses(t *testing.T) {
	f := newFakeDHT()
	install(t, f)
	installCallAt(t, &visits{}, nil)

	_, _ = Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second)
	// Pauses of 100, 200, 400, 800, 1000 ms put the lookups at about
	// 0, 0.1, 0.3, 0.7, 1.5 and 2.5 s; a fixed 100 ms would make about 30.
	if n := f.lookups(procedureKey()); n < 5 || n > 8 {
		t.Fatalf("DHT lookups within a 3 s deadline = %d, want 5 to 8", n)
	}
}

// A provider whose fetch fails is fetched from again only when its
// announcement changes, not on every pass over the DHT.
func TestGetDirectFetchesFromAFailingProviderOncePerAnnouncement(t *testing.T) {
	a := newStation(t, "a.test")
	mcid := testMcid()
	f := newFakeDHT()
	f.replies[dht.ContentKey(mcid[:])] = [][]dht.Record{{announcement(t, a, mcid)}}
	install(t, f)
	v := &visits{}
	installFetchAt(t, v, map[string]fetchAnswer{"a.test": {err: errors.New("test: content failed verification")}})

	if _, err := GetDirect(context.Background(), nil, mustIdentity(t), mcid, 2*time.Second); err == nil {
		t.Fatal("GetDirect succeeded, want the fetch failure")
	}
	if got := v.seen(); !equalHosts(got, "a.test") {
		t.Fatalf("fetches = %v, want one", got)
	}
}

// A station whose endpoint record changes partway through the deadline is
// reached at the new endpoint: the change is what makes it worth another dial.
func TestCallPicksUpAnEndpointRecordThatChangesMidDeadline(t *testing.T) {
	old := newStation(t, "a-old.test")
	moved := station{id: old.id, host: "a.test"}
	f := newFakeDHT()
	f.replies[procedureKey()] = [][]dht.Record{{advertisement(t, old, false)}}
	f.setEndpoint(old, endpointRecord(t, old))
	install(t, f)
	republished := endpointRecord(t, moved)
	time.AfterFunc(500*time.Millisecond, func() { f.setEndpoint(moved, republished) })
	v := &visits{}
	installCallAt(t, v, map[string]callAnswer{
		"a-old.test": {err: errUnreachable},
		"a.test":     {resp: okResponse, sent: true},
	})

	if _, err := Call(context.Background(), nil, mustIdentity(t), testRealm, testProcedure, cbor.Null(), 3*time.Second); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if got := v.seen(); !equalHosts(got, "a-old.test", "a.test") {
		t.Fatalf("dials = %v, want [a-old.test a.test]", got)
	}
}
