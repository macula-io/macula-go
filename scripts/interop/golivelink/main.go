// Command golivelink dials one live macula 12 station with stationlink and
// reports what the link settled on: the handshake time, the TLS key exchange
// group, cipher suite and leaf signature algorithm, and the station's
// capabilities; then holds the link for -hold and closes it with GOODBYE.
//
// With -serve, it then serves golivelink/echo under a throwaway test realm
// whose org directory and procedure delegation it signs itself and puts in the
// station's DHT, and calls it every -every for -serve from a second node's
// pool, by direct dial: the advertisement resolved from the DHT and checked
// against the test realm's key, the serving station dialed from its own
// endpoint record. Each outcome is reported, so a run long enough shows
// whether the station keeps routing to a provider whose advertisement is
// renewed on the same connection.
//
//	go run ./scripts/interop/golivelink -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <64 hex>
//	go run ./scripts/interop/golivelink ... -hold 0s -serve 14m -every 30s
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
	"github.com/macula-io/macula-go/ucan"
)

func main() {
	host := flag.String("host", "", "station host")
	port := flag.Uint("port", 4433, "station QUIC port")
	profileName := flag.String("profile", "pq_hybrid", "crypto profile")
	node := flag.String("node", "", "the station's node_id, 64 hex")
	hold := flag.Duration("hold", 5*time.Second, "how long to keep the link before closing it")
	serve := flag.Duration("serve", 0, "how long to serve golivelink/echo and call it, 0 for not at all")
	every := flag.Duration("every", 30*time.Second, "how often the caller calls while serving")
	flag.Parse()
	if err := run(*host, uint16(*port), *profileName, *node, *hold, *serve, *every); err != nil {
		fmt.Fprintln(os.Stderr, "golivelink:", err)
		os.Exit(1)
	}
}

func run(host string, port uint16, profileName, node string, hold, serve, every time.Duration) error {
	p, nodeID, err := parseTarget(profileName, node)
	if err != nil {
		return err
	}
	key, issuer, stopIssuer, err := newIdentity(p)
	if err != nil {
		return err
	}
	defer stopIssuer()
	ctx, cancel := context.WithTimeout(context.Background(), stationlink.HandshakeTimeout)
	defer cancel()
	link, err := dialAndReport(ctx, key, issuer, stationTarget(host, port, p, nodeID))
	if err != nil {
		return err
	}
	if err := dhtChecks(ctx, link, key, nodeID); err != nil {
		return err
	}
	if err := pubsubCheck(link); err != nil {
		return err
	}
	if err := holdLink(link, hold); err != nil {
		return err
	}
	if serve > 0 {
		if err := serveCheck(link, key, stationTarget(host, port, p, nodeID), serve, every); err != nil {
			return err
		}
	}
	return link.Close("client_stop")
}

// parseTarget is the profile to dial with, and the station's node_id.
func parseTarget(profileName, node string) (profile.Profile, [32]byte, error) {
	p, err := profile.Parse(profileName)
	if err != nil {
		return p, [32]byte{}, err
	}
	raw, err := hex.DecodeString(node)
	if err != nil || len(raw) != 32 {
		return p, [32]byte{}, fmt.Errorf("-node must be 64 hex")
	}
	var nodeID [32]byte
	copy(nodeID[:], raw)
	return p, nodeID, nil
}

// newIdentity generates this run's identity key and starts its statement
// issuer; the returned stop ends the issuer.
func newIdentity(p profile.Profile) (*identity.NodeKey, *identity.StatementIssuer, func(), error) {
	started := time.Now()
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return nil, nil, nil, err
	}
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return nil, nil, nil, err
	}
	running, stop := context.WithCancel(context.Background())
	go issuer.Run(running, nil)
	fmt.Printf("identity: %s, generated in %s\n", key, time.Since(started).Round(time.Millisecond))
	return key, issuer, stop, nil
}

// dialAndReport dials the station and prints what the handshake agreed, then
// calls _macula.ping once.
func dialAndReport(ctx context.Context, key *identity.NodeKey, issuer *identity.StatementIssuer, target transport.Target) (*stationlink.Link, error) {
	dialStarted := time.Now()
	link, err := stationlink.Dial(ctx, stationlink.Config{Target: target, IdentityKey: key, Issuer: issuer})
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	state := link.TLSState()
	leaf := state.PeerCertificates[0]
	fmt.Printf("handshake: accepted in %s\n", time.Since(dialStarted).Round(time.Millisecond))
	fmt.Printf("tls: group %s, suite %s, leaf %s, resumed %t\n",
		state.CurveID, tls.CipherSuiteName(state.CipherSuite), leaf.PublicKeyAlgorithm, state.DidResume)
	fmt.Printf("station: node_id %x, capabilities %d\n", link.StationNodeID(), link.StationCapabilities())
	callStarted := time.Now()
	_, err = link.Call(ctx, stationlink.Call{Procedure: "_macula.ping", Payload: cbor.Map(nil)})
	fmt.Printf("call _macula.ping: %v in %s\n", outcome(err), time.Since(callStarted).Round(time.Millisecond))
	return link, nil
}

// holdLink keeps the link up for hold, and reports a link that ended early.
func holdLink(link *stationlink.Link, hold time.Duration) error {
	select {
	case <-time.After(hold):
		fmt.Printf("held %s: still up, unrouted %v\n", hold, link.Unrouted())
		return nil
	case <-link.Done():
		return fmt.Errorf("the link ended while held: %w", link.Err())
	}
}

// stationTarget is the station as a dial target.
func stationTarget(host string, port uint16, p profile.Profile, nodeID [32]byte) transport.Target {
	return transport.Target{Host: host, Port: port, Profile: p, ExpectedNodeID: nodeID}
}

// serveCheck serves golivelink/echo on provider under a test realm and calls
// it from a second link every every, for serve.
func serveCheck(provider *stationlink.Link, providerKey *identity.NodeKey, target transport.Target, serve, every time.Duration) error {
	p := target.Profile
	realmName, realm, err := throwawayRealm()
	if err != nil {
		return err
	}
	realmKey, orgKey, err := realmKeys(p)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), stationlink.HandshakeTimeout)
	defer cancel()
	if err := putRealmRecords(ctx, provider, p, realm, realmKey, orgKey); err != nil {
		return err
	}
	echoed := func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }
	served, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: procedure, Handler: echoed, RealmKey: realmKey.PublicKey()})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	started := time.Now()
	fmt.Printf("serve %s: advertised, provider %x\n", procedure, provider.NodeID())
	caller, err := callerPool(ctx, p, target, realm, realmKey)
	if err != nil {
		return err
	}
	defer caller.Close()
	if err := streamCheck(ctx, provider, caller, realm, realmKey.PublicKey()); err != nil {
		return err
	}
	gated, cancelGated := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelGated()
	if err := gatedCheck(gated, provider, caller, p, realmName, realmKey.PublicKey()); err != nil {
		return err
	}
	return callLoop(provider, caller, served, realm, procedure, started, serve, every)
}

// The org and procedure a run serves on its throwaway realm.
const (
	org       = "golivelink"
	procedure = "golivelink/echo"
)

// throwawayRealm is a named realm of this run's own: its id is the name's
// SHA-256, as a realm's is, so the gated check's UCANs grant in it by name.
func throwawayRealm() (string, [32]byte, error) {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", [32]byte{}, err
	}
	name := "golivelink-" + hex.EncodeToString(suffix[:])
	return name, sha256.Sum256([]byte(name)), nil
}

func realmKeys(p profile.Profile) (realmKey, orgKey *identity.NodeKey, err error) {
	if realmKey, err = identity.GenerateKey(identity.PurposeIdentity, p); err != nil {
		return nil, nil, err
	}
	if orgKey, err = identity.GenerateKey(identity.PurposeIdentity, p); err != nil {
		return nil, nil, err
	}
	return realmKey, orgKey, nil
}

// putRealmRecords puts the throwaway realm's org directory and the org's
// delegation to the provider.
func putRealmRecords(ctx context.Context, provider *stationlink.Link, p profile.Profile, realm [32]byte,
	realmKey, orgKey *identity.NodeKey) error {
	orgKeyID := identity.KeyIDOf(orgKey.PublicKey(), p)
	directory := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("realm_id"), Val: cbor.Bytes(realm[:])},
		{Key: cbor.Text("org_name"), Val: cbor.Text(org)},
		{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
	})
	delegation := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("org_key"), Val: cbor.Bytes(orgKeyID[:])},
		{Key: cbor.Text("advertiser"), Val: cbor.Bytes(nodeIDBytes(provider))}})
	for _, signed := range []struct {
		t       record.Type
		payload cbor.Value
		key     *identity.NodeKey
	}{{record.TypeOrgDirectory, directory, realmKey}, {record.TypeProcedureDelegation, delegation, orgKey}} {
		if err := putSigned(ctx, provider, signed.t, signed.payload, signed.key); err != nil {
			return err
		}
	}
	return nil
}

// callerPool is the caller's own pool: one seed, trusting the throwaway realm.
func callerPool(ctx context.Context, p profile.Profile, target transport.Target, realm [32]byte, realmKey *identity.NodeKey) (*pool.Pool, error) {
	callerKey, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return nil, err
	}
	caller, err := pool.Connect(ctx, []pool.Seed{{Host: target.Host, Port: target.Port, NodeID: target.ExpectedNodeID}},
		pool.Opts{IdentityKey: callerKey, RealmTrust: map[[32]byte][]byte{realm: realmKey.PublicKey()}})
	if err != nil {
		return nil, fmt.Errorf("the caller's pool: %w", err)
	}
	return caller, nil
}

// callLoop calls the served procedure every every, until serve is over.
func callLoop(provider *stationlink.Link, caller *pool.Pool, served *stationlink.Served, realm [32]byte, procedure string,
	started time.Time, serve, every time.Duration) error {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		callStarted := time.Now()
		_, err := caller.Call(context.Background(), pool.Call{Realm: realm, Procedure: procedure,
			Payload: cbor.Text("echo"), Timeout: 5 * time.Second})
		fmt.Printf("t+%s call %s (direct dial): %s in %s\n", time.Since(started).Round(time.Second), procedure, outcome(err),
			time.Since(callStarted).Round(time.Millisecond))
		select {
		case <-served.Done():
			fmt.Printf("t+%s served ended: %v\n", time.Since(started).Round(time.Second), served.Err())
		default:
		}
		if time.Since(started) >= serve {
			return served.Stop()
		}
		select {
		case <-ticker.C:
		case <-provider.Done():
			return fmt.Errorf("the provider's link ended: %w", provider.Err())
		}
	}
}

// putSigned signs a wire 1.0 record of type t with key, living 30 minutes (a procedure delegation's row; an org
// directory's is 6 hours), and puts it. A
// Go key is an identity or CONNECT key only, so the test realm's and org's
// records are signed as the signed objects they are, under the record label,
// as a realm and an org sign them.
// lifetimeRows are the lifetime rows of the records putSigned signs
// (WIRE_1_0.md section 5.1).
var lifetimeRows = map[record.Type]uint64{record.TypeOrgDirectory: 2, record.TypeProcedureDelegation: 1}

func putSigned(ctx context.Context, link *stationlink.Link, t record.Type, payload cbor.Value, key *identity.NodeKey) error {
	version, err := uuid.NewV7()
	if err != nil {
		return err
	}
	now := uint64(time.Now().UnixMilli())
	object, err := identity.SignObject("MACULA-PQ-RECORD-V1", []cbor.MapEntry{
		{Key: cbor.Text("type"), Val: cbor.Uint64(uint64(t))},
		{Key: cbor.Text("version"), Val: cbor.Bytes(version[:])},
		{Key: cbor.Text("created_at"), Val: cbor.Uint64(now)},
		{Key: cbor.Text("expires_at"), Val: cbor.Uint64(now + 30*60_000)},
		{Key: cbor.Text("schema"), Val: cbor.Uint64(record.Schema)},
		{Key: cbor.Text("lifetime_class"), Val: cbor.Uint64(lifetimeRows[t])},
		{Key: cbor.Text("payload"), Val: payload},
	}, key)
	if err != nil {
		return fmt.Errorf("sign %#x: %w", uint8(t), err)
	}
	wire := cbor.Encode(object.Value())
	if err := link.PutRecord(ctx, wire); err != nil {
		return fmt.Errorf("put %#x: %w", uint8(t), err)
	}
	return nil
}

// pubsubCheck subscribes to a topic, publishes on it, and waits for the
// station to deliver the publication back as a verified event.
func pubsubCheck(link *stationlink.Link) error {
	realm := [32]byte{0x6c}
	topic := "io.macula/golivelink/live/check/publication_heard_v1"
	sub, err := link.Subscribe(realm, topic)
	if err != nil {
		return err
	}
	defer sub.Unsubscribe()
	time.Sleep(200 * time.Millisecond)
	started := time.Now()
	if err := link.Publish(stationlink.Publication{Realm: realm, Topic: topic, Payload: cbor.Text("heard")}); err != nil {
		return err
	}
	select {
	case event := <-sub.Events():
		text, _ := event.Payload.AsText()
		fmt.Printf("pubsub: event %q from %x via %s in %s\n", text, event.Publisher[:4], event.DeliveredVia,
			time.Since(started).Round(time.Millisecond))
	case <-time.After(5 * time.Second):
		fmt.Printf("pubsub: no event within 5s; unrouted %v\n", link.Unrouted())
	}
	return nil
}

// outcome is a call's error in one line, or "RESULT".
func outcome(err error) string {
	if err != nil {
		return "error " + err.Error()
	}
	return "RESULT"
}

// dhtChecks reads the station's own records from its DHT, verified, then puts
// a node record this client signs and finds it again.
func dhtChecks(ctx context.Context, link *stationlink.Link, key *identity.NodeKey, station [32]byte) error {
	started := time.Now()
	nodes, dropped, err := link.FindRecordsByType(ctx, record.TypeNodeRecord)
	fmt.Printf("dht find_records_by_type node_record: %d verified, %d dropped, %v in %s\n",
		len(nodes), dropped, outcome(err), time.Since(started).Round(time.Millisecond))
	started = time.Now()
	endpoint, err := link.FindRecord(ctx, record.StationEndpointKey(station))
	fmt.Printf("dht find_record station_endpoint: type %#x, %v in %s\n",
		uint8(endpoint.Record().Type), outcome(err), time.Since(started).Round(time.Millisecond))
	nodeID, err := key.NodeID()
	if err != nil {
		return err
	}
	unsigned, err := record.NewNodeRecord(nodeID, nil, 0, record.NodeRecordOptions{DisplayName: "golivelink"})
	if err != nil {
		return err
	}
	signed, err := record.Sign(unsigned, key)
	if err != nil {
		return err
	}
	wire, err := record.Encode(signed)
	if err != nil {
		return err
	}
	started = time.Now()
	err = link.PutRecord(ctx, wire)
	fmt.Printf("dht put_record own node_record (%d bytes): %v in %s\n", len(wire), outcome(err), time.Since(started).Round(time.Millisecond))
	storageKey, err := record.StorageKey(signed)
	if err != nil {
		return err
	}
	found, err := link.FindRecord(ctx, storageKey)
	fmt.Printf("dht find_record own node_record: type %#x, %v\n", uint8(found.Record().Type), outcome(err))
	return nil
}

func nodeIDBytes(link *stationlink.Link) []byte {
	id := link.NodeID()
	return id[:]
}

// streamCheck serves golivelink/watch as a server stream of three chunks and
// opens it from the caller's pool by direct dial, reporting when each chunk
// and the end arrive.
func streamCheck(ctx context.Context, provider *stationlink.Link, caller *pool.Pool, realm [32]byte, realmKey []byte) error {
	const watch = "golivelink/watch"
	served, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: watch, RealmKey: realmKey,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			for _, chunk := range []string{"one", "two", "three"} {
				if err := s.Send([]byte(chunk)); err != nil {
					return err
				}
			}
			return s.Close()
		}}})
	if err != nil {
		return fmt.Errorf("serve %s: %w", watch, err)
	}
	defer served.Stop()
	started := time.Now()
	stream, err := caller.OpenStream(ctx, pool.StreamCall{Realm: realm, Procedure: watch, Mode: frame.ServerStream, Payload: cbor.Map(nil)})
	if err != nil {
		return fmt.Errorf("open %s: %w", watch, err)
	}
	for {
		event, err := stream.Recv(ctx)
		if err != nil {
			fmt.Printf("stream %s: %v after %s\n", watch, err, time.Since(started).Round(time.Millisecond))
			return nil
		}
		body, _ := event.Body.AsBytes()
		switch event.Kind {
		case stationlink.StreamData:
			fmt.Printf("stream %s: chunk %q at %s\n", watch, body, time.Since(started).Round(time.Millisecond))
		case stationlink.StreamEnd:
			fmt.Printf("stream %s: end at %s\n", watch, time.Since(started).Round(time.Millisecond))
			return clientStreamCheck(ctx, provider, caller, realm, realmKey)
		}
	}
}

// clientStreamCheck serves golivelink/count as a client stream that answers
// with how many bytes it heard, and sends it three chunks from the caller's
// pool: the caller's signed frames cross the station too.
func clientStreamCheck(ctx context.Context, provider *stationlink.Link, caller *pool.Pool, realm [32]byte, realmKey []byte) error {
	const count = "golivelink/count"
	served, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: count, RealmKey: realmKey,
		Stream: &stationlink.StreamOffer{Mode: frame.ClientStream, Handler: func(ctx context.Context, s *stationlink.Stream) error {
			total := 0
			for {
				event, err := s.Recv(ctx)
				if err != nil {
					return err
				}
				if event.Kind == stationlink.StreamEnd {
					return s.Reply(cbor.Uint64(uint64(total)))
				}
				body, _ := event.Body.AsBytes()
				total += len(body)
			}
		}}})
	if err != nil {
		return fmt.Errorf("serve %s: %w", count, err)
	}
	defer served.Stop()
	started := time.Now()
	stream, err := caller.OpenStream(ctx, pool.StreamCall{Realm: realm, Procedure: count, Mode: frame.ClientStream, Payload: cbor.Map(nil)})
	if err != nil {
		return fmt.Errorf("open %s: %w", count, err)
	}
	for _, chunk := range []string{"ab", "cde", "f"} {
		if err := stream.Send([]byte(chunk)); err != nil {
			return fmt.Errorf("send on %s: %w", count, err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		return err
	}
	event, err := stream.Recv(ctx)
	if err != nil {
		fmt.Printf("stream %s: %v after %s\n", count, err, time.Since(started).Round(time.Millisecond))
		return nil
	}
	total, _ := event.Payload.AsInt64()
	fmt.Printf("stream %s: reply %d bytes at %s\n", count, total, time.Since(started).Round(time.Millisecond))
	return nil
}

// gatedCheck serves golivelink/gated and golivelink/gated_watch on provider
// gated on a fresh root node, and presents them what a gated provider must
// judge as macula's link does, through the live station: no token
// (unauthorized), the root's grant to the caller (served), and that grant with
// a proof no token names (malformed_frame). Any other answer fails the run.
func gatedCheck(ctx context.Context, provider *stationlink.Link, caller *pool.Pool, p profile.Profile, realmName string,
	realmKey []byte) error {
	const call, watch = "golivelink/gated", "golivelink/gated_watch"
	realm := sha256.Sum256([]byte(realmName))
	root, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	rootID, err := root.NodeID()
	if err != nil {
		return err
	}
	policy := ucan.UCANRequired{Issuer: rootID}
	stop, err := serveGated(ctx, provider, realm, realmKey, policy, call, watch)
	if err != nil {
		return err
	}
	defer stop()
	grant := func(audience [32]byte) ([]byte, error) {
		return ucan.Create(root, audience, []ucan.Capability{{With: "mri:org:" + realmName + "/golivelink", Can: "invoke"}},
			ucan.Options{Exp: time.Now().Unix() + 300})
	}
	token, err := grant(caller.NodeID())
	if err != nil {
		return err
	}
	stray, err := grant(provider.NodeID())
	if err != nil {
		return err
	}
	for _, c := range gatedCases(token, stray) {
		if err := checkGatedCase(ctx, caller, realm, call, watch, c); err != nil {
			return err
		}
	}
	return nil
}

// serveGated serves the gated call and stream on provider, both on policy.
func serveGated(ctx context.Context, provider *stationlink.Link, realm [32]byte, realmKey []byte,
	policy ucan.UCANRequired, call, watch string) (func(), error) {
	calls, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: call, RealmKey: realmKey, Policy: policy,
		Handler: func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return cbor.Text("served"), nil }})
	if err != nil {
		return nil, fmt.Errorf("serve %s: %w", call, err)
	}
	streams, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: watch, RealmKey: realmKey, Policy: policy,
		Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			return s.Send([]byte("served"))
		}}})
	if err != nil {
		_ = calls.Stop()
		return nil, fmt.Errorf("serve %s: %w", watch, err)
	}
	return func() {
		_ = calls.Stop()
		_ = streams.Stop()
	}, nil
}

// gatedCase is one token case a gated provider must judge.
type gatedCase struct {
	name   string
	token  []byte
	proofs [][]byte
	want   string
}

// gatedCases is what a gated provider must judge as macula's link does: no
// token (unauthorized), the root's grant to the caller (served), and that
// grant with a proof no token names (malformed_frame).
func gatedCases(token, stray []byte) []gatedCase {
	return []gatedCase{
		{"no token", nil, nil, "unauthorized"},
		{"the root's grant", token, nil, ""},
		{"a proof no token names", token, [][]byte{stray}, "malformed_frame"},
	}
}

// checkGatedCase presents one case as a call and as an open, and wants the
// same answer to both.
func checkGatedCase(ctx context.Context, caller *pool.Pool, realm [32]byte, call, watch string, c gatedCase) error {
	_, err := caller.Call(ctx, pool.Call{Realm: realm, Procedure: call, Payload: cbor.Map(nil), Timeout: 10 * time.Second,
		Token: c.token, Proofs: c.proofs})
	fmt.Printf("gated call, %s: %s\n", c.name, outcome(err))
	if got := refusedWith(err); got != c.want {
		return fmt.Errorf("gated call, %s: %v, want %q", c.name, err, c.want)
	}
	recvCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := caller.OpenStream(ctx, pool.StreamCall{Realm: realm, Procedure: watch, Mode: frame.ServerStream,
		Payload: cbor.Map(nil), Token: c.token, Proofs: c.proofs})
	if err != nil {
		return fmt.Errorf("gated open, %s: %w", c.name, err)
	}
	_, err = stream.Recv(recvCtx)
	_ = stream.Close()
	fmt.Printf("gated open, %s: %s\n", c.name, outcome(err))
	if got := refusedWith(err); got != c.want {
		return fmt.Errorf("gated open, %s: %v, want %q", c.name, err, c.want)
	}
	return nil
}

// refusedWith is the code a provider refused a call or an open with, "" for
// none, or the error's text for any other failure, which matches no code.
func refusedWith(err error) string {
	var provided *stationlink.ProviderError
	var stream *stationlink.StreamError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &provided):
		return provided.Code
	case errors.As(err, &stream) && !stream.Relay:
		return stream.Code
	}
	return err.Error()
}
