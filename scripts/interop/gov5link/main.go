// Command gov5link is macula-go's side of the live handshake v5 check (scripts/interop/v5.sh): it dials one
// running station with stationlink, reports the handshake version, the TLS group and whether the session resumed,
// holds the link for -hold while the station probes it with liveness_ping, and reports whether the link is still
// up. It exits non-zero unless the link was version 5, not resumed, and survived the hold.
//
//	go run ./scripts/interop/gov5link -host 127.0.0.1 -port 44330 -profile pq_hybrid -node <64 hex> -hold 5s
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

func main() {
	host := flag.String("host", "127.0.0.1", "the station's host")
	port := flag.Uint("port", 0, "the station's port")
	profileName := flag.String("profile", "pq_hybrid", "pq_pure or pq_hybrid")
	node := flag.String("node", "", "the station's node_id, 64 hex")
	hold := flag.Duration("hold", 5*time.Second, "how long to hold the link")
	flag.Parse()
	if err := run(*host, uint16(*port), *profileName, *node, *hold); err != nil {
		fmt.Println("gov5link:", err)
		fmt.Println("verdict: FAIL")
		os.Exit(1)
	}
	fmt.Println("verdict: PASS")
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
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return err
	}
	running, stopIssuer := context.WithCancel(context.Background())
	defer stopIssuer()
	go issuer.Run(running, nil)
	ctx, cancel := context.WithTimeout(context.Background(), stationlink.HandshakeTimeout)
	defer cancel()
	link, err := stationlink.Dial(ctx, stationlink.Config{
		Target:      transport.Target{Host: host, Port: port, Profile: p, ExpectedNodeID: nodeID},
		IdentityKey: key, Issuer: issuer,
	})
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer link.Close("gov5link_done")
	state := link.TLSState()
	fmt.Printf("handshake: version %d, tls group %s, resumed %t\n", link.HandshakeVersion(), state.CurveID, state.DidResume)
	fmt.Printf("counters: %v\n", stationlink.HandshakeCounters())
	select {
	case <-link.Done():
		return fmt.Errorf("the link ended during the hold: %w", link.Err())
	case <-time.After(hold):
	}
	fmt.Printf("held %s: the link is up\n", hold)
	switch {
	case link.HandshakeVersion() != 5:
		return fmt.Errorf("handshake version %d, want 5", link.HandshakeVersion())
	case state.DidResume:
		return fmt.Errorf("the TLS session resumed")
	}
	return nil
}
