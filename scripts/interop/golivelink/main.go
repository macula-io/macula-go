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
	for _, c := range []struct {
		name string
		call stationlink.Call
	}{
		{"_macula.ping", stationlink.Call{Procedure: "_macula.ping", Payload: cbor.Map(nil)}},
		{"_dht.find_records_by_type node_record", stationlink.Call{Procedure: "_dht.find_records_by_type",
			Payload: cbor.Map([]cbor.MapEntry{{Key: cbor.Text("type"), Val: cbor.Uint64(0x01)}})}},
	} {
		callStarted := time.Now()
		result, err := link.Call(ctx, c.call)
		fmt.Printf("call %s: %s in %s\n", c.name, describe(result, err), time.Since(callStarted).Round(time.Millisecond))
	}
	select {
	case <-time.After(hold):
		fmt.Printf("held %s: still up, unrouted %v\n", hold, link.Unrouted())
	case <-link.Done():
		return fmt.Errorf("the link ended while held: %w", link.Err())
	}
	return link.Close("client_stop")
}

// describe is a call's outcome in one line: the result's shape, or the error.
func describe(result cbor.Value, err error) string {
	if err != nil {
		return "error " + err.Error()
	}
	if list, isList := result.AsList(); isList {
		return fmt.Sprintf("RESULT, a list of %d", len(list))
	}
	if text, isText := result.AsText(); isText {
		return fmt.Sprintf("RESULT %q", text)
	}
	return fmt.Sprintf("RESULT %v", result)
}
