// Command golivelink dials one live macula 12 station with stationlink and
// reports what the link settled on: the handshake time, the TLS key exchange
// group, cipher suite and leaf signature algorithm, and the station's
// capabilities; then holds the link for -hold and closes it with GOODBYE.
//
//	go run ./scripts/interop/golivelink -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <64 hex>
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

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
	flag.Parse()
	if err := run(*host, uint16(*port), *profileName, *node, *hold); err != nil {
		fmt.Fprintln(os.Stderr, "golivelink:", err)
		os.Exit(1)
	}
}

func run(host string, port uint16, profileName, node string, hold time.Duration) error {
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
	return link.Close("client_stop")
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
