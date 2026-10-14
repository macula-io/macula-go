// Command gogroups is macula-go's side of sealed groups across macula 13.2 and
// macula-go, for scripts/interop/groups.sh and erlang_groups.escript, through
// one station and macula's own distributor (macula_group_keys).
//
//	gogroups -station host:port@<node_id hex> -profile pq_hybrid -realm <hex> -realm-key <hex> -work <dir> -prefix <p> -topic <t> member
//	gogroups ... stranger
//
// Both print "node <hex>" and wait for <work>/grant.<hex>, the org's grant the
// script minted for this node. member subscribes to topic under the group
// prefix, pulling its epoch from the Erlang distributor, writes
// <work>/ready.go, waits for <work>/ready.erlang, publishes "from go" sealed
// under the group, and waits for the Erlang member's "from erlang" to arrive
// opened. stranger, a node the distributor's removed set names, checks its
// subscribe is refused not_a_member. Each prints its outcome and exits 1 on
// any other.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/group"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
)

type config struct {
	station, profile, realm, realmKey, work, prefix, topic string
}

func main() {
	var c config
	flag.StringVar(&c.station, "station", "", "host:port@<node_id hex>")
	flag.StringVar(&c.profile, "profile", "pq_hybrid", "crypto profile")
	flag.StringVar(&c.realm, "realm", "", "realm id, hex")
	flag.StringVar(&c.realmKey, "realm-key", "", "the realm key the pool pins, hex")
	flag.StringVar(&c.work, "work", "", "the directory grants and barriers are files in")
	flag.StringVar(&c.prefix, "prefix", "", "the group prefix")
	flag.StringVar(&c.topic, "topic", "", "the topic under it")
	flag.Parse()
	if err := run(flag.Arg(0), c); err != nil {
		fmt.Fprintln(os.Stderr, "gogroups:", err)
		os.Exit(1)
	}
}

func run(mode string, c config) error {
	p, err := profile.Parse(c.profile)
	if err != nil {
		return err
	}
	seed, err := parseSeed(c.station)
	if err != nil {
		return err
	}
	realm, err := id32(c.realm)
	if err != nil {
		return err
	}
	realmKey, err := hex.DecodeString(c.realmKey)
	if err != nil {
		return err
	}
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	node, err := pool.Connect(ctx, []pool.Seed{seed}, pool.Opts{IdentityKey: key, RealmTrust: map[[32]byte][]byte{realm: realmKey}})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer node.Close()
	self := node.NodeID()
	fmt.Printf("node %s\n", hex.EncodeToString(self[:]))
	grant, err := waited(ctx, filepath.Join(c.work, "grant."+hex.EncodeToString(self[:])))
	if err != nil {
		return err
	}
	g := pool.Group{Prefix: c.prefix, UCAN: []byte(strings.TrimSpace(grant))}
	switch mode {
	case "member":
		return member(ctx, node, realm, c, g)
	case "stranger":
		_, err := subscribed(ctx, node, realm, c.topic, g)
		reason, _ := group.ReasonOf(err)
		fmt.Printf("stranger subscribe: %v\n", err)
		if reason != group.ReasonNotAMember {
			return errors.New("the stranger was not refused not_a_member")
		}
		return nil
	}
	return fmt.Errorf("mode %q is member or stranger", mode)
}

func member(ctx context.Context, node *pool.Pool, realm [32]byte, c config, g pool.Group) error {
	sub, err := subscribed(ctx, node, realm, c.topic, g)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	fmt.Println("subscribed")
	if err := os.WriteFile(filepath.Join(c.work, "ready.go"), nil, 0o644); err != nil {
		return err
	}
	if _, err := waited(ctx, filepath.Join(c.work, "ready.erlang")); err != nil {
		return err
	}
	if err := node.PublishGroup(ctx, stationlink.Publication{Realm: realm, Topic: c.topic, Payload: cbor.Text("from go")}, g); err != nil {
		return fmt.Errorf("publish: %w", err)
	}
	fmt.Println("published")
	deadline := time.After(time.Minute)
	for {
		select {
		case e := <-sub.Events():
			text, _ := e.Payload.AsText()
			switch {
			case e.Unopened != "":
				return fmt.Errorf("an event unopened: %s", e.Unopened)
			case text == "from go":
			case e.Sealed != nil && text == "from erlang":
				fmt.Printf("opened from erlang under %x\n", e.Sealed.KeyID)
				return nil
			default:
				return fmt.Errorf("unexpected event: sealed %v, payload %v", e.Sealed != nil, e.Payload)
			}
		case <-deadline:
			return errors.New("nothing from erlang")
		}
	}
}

// subscribed subscribes under g, waiting while the distributor's
// advertisement has not reached the DHT yet.
func subscribed(ctx context.Context, node *pool.Pool, realm [32]byte, topic string, g pool.Group) (*pool.Subscription, error) {
	for range 150 {
		sub, err := node.SubscribeGroup(ctx, realm, topic, g)
		if reason, _ := group.ReasonOf(err); reason != group.ReasonNoDistributor {
			return sub, err
		}
		time.Sleep(200 * time.Millisecond)
	}
	return node.SubscribeGroup(ctx, realm, topic, g)
}

// waited is a file the orchestrating script writes, read once it is there.
func waited(ctx context.Context, path string) (string, error) {
	for {
		if b, err := os.ReadFile(path); err == nil {
			return string(b), nil
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("no %s", path)
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func parseSeed(s string) (pool.Seed, error) {
	addr, nodeHex, ok := strings.Cut(s, "@")
	if !ok {
		return pool.Seed{}, errors.New("-station is host:port@<node_id hex>")
	}
	host, portText, ok := strings.Cut(addr, ":")
	port, err := strconv.ParseUint(portText, 10, 16)
	if !ok || err != nil {
		return pool.Seed{}, errors.New("-station is host:port@<node_id hex>")
	}
	node, err := id32(nodeHex)
	if err != nil {
		return pool.Seed{}, err
	}
	return pool.Seed{Host: host, Port: uint16(port), NodeID: node}, nil
}

func id32(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%q is not a 32-byte id in hex", s)
	}
	return [32]byte(b), nil
}
