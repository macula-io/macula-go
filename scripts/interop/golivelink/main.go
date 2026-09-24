// Command golivelink dials one live macula 12 station with stationlink and
// reports what the link settled on: the handshake time, the TLS key exchange
// group, cipher suite and leaf signature algorithm, and the station's
// capabilities; then holds the link for -hold and closes it with GOODBYE.
//
// With -serve, it then serves golivelink/echo under a throwaway test realm
// whose org directory and procedure delegation it signs itself and puts in the
// station's DHT, and calls it from a second link every -every for -serve,
// reporting each outcome: whether a station keeps routing to a provider whose
// advertisement is renewed on the same connection.
//
//	go run ./scripts/interop/golivelink -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <64 hex>
//	go run ./scripts/interop/golivelink ... -hold 0s -serve 14m -every 30s
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
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
	p, err := profile.Parse(profileName)
	if err != nil {
		return err
	}
	raw, err := hex.DecodeString(node)
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("-node must be 64 hex")
	}
	var nodeID [32]byte
	copy(nodeID[:], raw)
	started := time.Now()
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return err
	}
	fmt.Printf("identity: %s, generated in %s\n", key, time.Since(started).Round(time.Millisecond))
	ctx, cancel := context.WithTimeout(context.Background(), stationlink.HandshakeTimeout)
	defer cancel()
	dialStarted := time.Now()
	link, err := stationlink.Dial(ctx, stationlink.Config{
		Target:      transport.Target{Host: host, Port: port, Profile: p, ExpectedNodeID: nodeID},
		IdentityKey: key, Issuer: issuer,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
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
	if err := dhtChecks(ctx, link, key, nodeID); err != nil {
		return err
	}
	if err := pubsubCheck(link); err != nil {
		return err
	}
	select {
	case <-time.After(hold):
		fmt.Printf("held %s: still up, unrouted %v\n", hold, link.Unrouted())
	case <-link.Done():
		return fmt.Errorf("the link ended while held: %w", link.Err())
	}
	if serve > 0 {
		if err := serveCheck(link, key, stationTarget(host, port, p, nodeID), serve, every); err != nil {
			return err
		}
	}
	return link.Close("client_stop")
}

// stationTarget is the station as a dial target.
func stationTarget(host string, port uint16, p profile.Profile, nodeID [32]byte) transport.Target {
	return transport.Target{Host: host, Port: port, Profile: p, ExpectedNodeID: nodeID}
}

// serveCheck serves golivelink/echo on provider under a test realm and calls
// it from a second link every every, for serve.
func serveCheck(provider *stationlink.Link, providerKey *identity.NodeKey, target transport.Target, serve, every time.Duration) error {
	p := target.Profile
	var realm [32]byte
	if _, err := rand.Read(realm[:]); err != nil {
		return err
	}
	const org, procedure = "golivelink", "golivelink/echo"
	realmKey, err := identity.GenerateKey(identity.PurposeIdentity, p)
	if err != nil {
		return err
	}
	orgKey, err := identity.GenerateKey(identity.PurposeIdentity, p)
	if err != nil {
		return err
	}
	orgKeyID := identity.KeyIDOf(orgKey.PublicKey(), p)
	ctx, cancel := context.WithTimeout(context.Background(), stationlink.HandshakeTimeout)
	defer cancel()
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
	echoed := func(_ context.Context, r stationlink.Request) (cbor.Value, error) { return r.Payload, nil }
	served, err := provider.Serve(ctx, stationlink.Offer{Realm: realm, Procedure: procedure, Handler: echoed, RealmKey: realmKey.PublicKey()})
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	started := time.Now()
	fmt.Printf("serve %s: advertised, provider %x\n", procedure, provider.NodeID())
	callerKey, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	issuer, err := identity.NewStatementIssuer(callerKey, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return err
	}
	caller, err := stationlink.Dial(ctx, stationlink.Config{Target: target, IdentityKey: callerKey, Issuer: issuer})
	if err != nil {
		return fmt.Errorf("dial the caller: %w", err)
	}
	defer caller.Close("client_stop")
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		callStarted := time.Now()
		_, err := caller.Call(context.Background(), stationlink.Call{Realm: realm, Procedure: procedure,
			Target: provider.NodeID(), Payload: cbor.Text("echo"), Timeout: 5 * time.Second})
		fmt.Printf("t+%s call %s: %s in %s\n", time.Since(started).Round(time.Second), procedure, outcome(err),
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
		case <-caller.Done():
			return fmt.Errorf("the caller's link ended: %w", caller.Err())
		}
	}
}

// putSigned signs a record of type t with key, living an hour (a realm or org record lives at most 6), and puts it. A
// Go key is an identity or CONNECT key only, so the test realm's and org's
// records are signed as the signed objects they are, under the record label,
// as a realm and an org sign them.
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
		{Key: cbor.Text("expires_at"), Val: cbor.Uint64(now + 3_600_000)},
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
