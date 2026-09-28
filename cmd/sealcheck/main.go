// Command sealcheck is M4's measurement: from outside the fleet, it makes sealed
// calls and a sealed stream to a provider through the stations, the same calls
// in the clear against a plain provider, and records each caller's seal report
// (macula's DESIGN_E2E_SEAL_REPORT), the key the provider's advertisement names,
// the serving station and the latency. It exits non-zero unless every sealed
// report is sealed to the key the provider's own advertisement names.
//
//	sealcheck -realm <hex> -realm-key <hex> -seed host:port@<node hex> [-seed ...] \
//	    [-sealed mcl-echo/echo_sealed] [-stream-procedure mcl-echo/echo_sealed_stream] \
//	    [-clear mcl-echo/echo] [-provider <node hex>] [-n 20] [-call=true] [-stream=true] \
//	    [-profile pq_pure] [-timeout 10s]
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
)

type seeds []pool.Seed

func (s *seeds) String() string { return fmt.Sprint(len(*s)) }

// Set reads host:port@<node_id hex>.
func (s *seeds) Set(text string) error {
	at := strings.LastIndex(text, "@")
	colon := strings.LastIndex(text[:max(at, 0)], ":")
	if at < 0 || colon < 0 {
		return fmt.Errorf("a seed is host:port@<node_id hex>, not %q", text)
	}
	port, err := strconv.ParseUint(text[colon+1:at], 10, 16)
	if err != nil {
		return fmt.Errorf("the seed's port: %w", err)
	}
	node, err := hexID("the seed's node_id", text[at+1:])
	if err != nil {
		return err
	}
	*s = append(*s, pool.Seed{Host: strings.Trim(text[:colon], "[]"), Port: uint16(port), NodeID: node})
	return nil
}

func main() {
	var cfg config
	var seedList seeds
	flag.Var(&seedList, "seed", "a station to link to, host:port@<node_id hex> (repeatable)")
	realmHex := flag.String("realm", "", "the realm id, hex")
	realmKeyHex := flag.String("realm-key", "", "the realm's pinned key, hex, as carried")
	profileName := flag.String("profile", "pq_pure", "the crypto profile")
	providerHex := flag.String("provider", "", "pin the sealed provider's node_id, hex (any trusted one when empty)")
	flag.StringVar(&cfg.Sealed, "sealed", "mcl-echo/echo_sealed", "the sealed unary procedure")
	flag.StringVar(&cfg.StreamProcedure, "stream-procedure", "mcl-echo/echo_sealed_stream", "the sealed server-stream procedure")
	flag.StringVar(&cfg.Clear, "clear", "mcl-echo/echo", "the plain procedure for the clear leg (empty for none)")
	flag.IntVar(&cfg.N, "n", 20, "how many sealed calls, and as many clear ones")
	flag.IntVar(&cfg.Chunks, "chunks", 3, "how many chunks the stream asks for")
	flag.BoolVar(&cfg.Call, "call", true, "run the call leg")
	flag.BoolVar(&cfg.Stream, "stream", true, "run the stream leg")
	flag.DurationVar(&cfg.Timeout, "timeout", 10*time.Second, "each call's timeout, and the wait for advertisements")
	flag.Parse()
	if err := configured(&cfg, seedList, *realmHex, *realmKeyHex, *profileName, *providerHex); err != nil {
		fmt.Fprintln(os.Stderr, "sealcheck:", err)
		os.Exit(2)
	}
	if err := measure(context.Background(), cfg, os.Stdout); err != nil {
		os.Exit(1)
	}
}

func configured(cfg *config, seedList seeds, realmHex, realmKeyHex, profileName, providerHex string) error {
	if len(seedList) == 0 {
		return fmt.Errorf("at least one -seed")
	}
	cfg.Seeds = seedList
	realm, err := hexID("-realm", realmHex)
	if err != nil {
		return err
	}
	cfg.Realm = realm
	if cfg.RealmKey, err = hex.DecodeString(realmKeyHex); err != nil || len(cfg.RealmKey) == 0 {
		return fmt.Errorf("-realm-key is the realm's key as carried, in hex")
	}
	switch profile.Profile(profileName) {
	case profile.PQPure, profile.PQHybrid:
		cfg.Profile = profile.Profile(profileName)
	default:
		return fmt.Errorf("-profile is pq_pure or pq_hybrid, not %q", profileName)
	}
	if providerHex != "" {
		id, err := hexID("-provider", providerHex)
		if err != nil {
			return err
		}
		cfg.Provider = &id
	}
	if !cfg.Call && !cfg.Stream {
		return fmt.Errorf("at least one of -call and -stream")
	}
	return nil
}
