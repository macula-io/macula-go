// Command gocontent shares or fetches node-served content (macula 12.6.0,
// D27) through one station, for the cross-check against macula's Erlang
// sharer and fetcher (see scripts/interop/README.md).
//
//	gocontent -host 127.0.0.1 -port 44330 -node <station node_id> -realm <hex> -share 600000 -hold 2m
//	gocontent -host 127.0.0.1 -port 44330 -node <station node_id> -realm <hex> -fetch <mcid hex>
//
// Shared bytes are the pattern i mod 251, the same as the Erlang script's, so
// either side can check the other's content by its SHA-384.
package main

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
)

func main() {
	host := flag.String("host", "127.0.0.1", "station host")
	port := flag.Int("port", 4433, "station port")
	node := flag.String("node", "", "the station's node_id, 64 hex")
	profileName := flag.String("profile", "pq_hybrid", "crypto profile")
	realmHex := flag.String("realm", "", "realm id, 64 hex")
	share := flag.Int("share", -1, "share this many pattern bytes and print the MCID")
	hold := flag.Duration("hold", time.Minute, "how long to share before unsharing")
	after := flag.Duration("after", 30*time.Second, "how long to stay linked after unsharing")
	fetch := flag.String("fetch", "", "fetch the content with this MCID, hex")
	flag.Parse()
	if err := run(*host, *port, *node, *profileName, *realmHex, *share, *hold, *after, *fetch); err != nil {
		fmt.Fprintln(os.Stderr, "gocontent:", err)
		os.Exit(1)
	}
}

func run(host string, port int, nodeHex, profileName, realmHex string, share int, hold, after time.Duration, fetch string) error {
	p, err := profile.Parse(profileName)
	if err != nil {
		return err
	}
	var station, realm [32]byte
	if err := decode32(nodeHex, &station); err != nil {
		return fmt.Errorf("-node: %w", err)
	}
	if err := decode32(realmHex, &realm); err != nil {
		return fmt.Errorf("-realm: %w", err)
	}
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), hold+after+time.Minute)
	defer cancel()
	pl, err := pool.Connect(ctx, []pool.Seed{{Host: host, Port: uint16(port), NodeID: station}}, pool.Opts{IdentityKey: key})
	if err != nil {
		return err
	}
	defer pl.Close()
	self := pl.NodeID()
	fmt.Printf("node %s\n", hex.EncodeToString(self[:]))
	switch {
	case share >= 0:
		data := pattern(share)
		start := time.Now()
		mcid, err := pl.ShareContent(ctx, realm, data, "gocontent.bin")
		if err != nil {
			return err
		}
		fmt.Printf("shared %s %d bytes sha384 %s in %s\n", hex.EncodeToString(mcid[:]), len(data), sum(data), time.Since(start).Round(time.Millisecond))
		time.Sleep(hold)
		if err := pl.UnshareContent(ctx, realm, mcid); err != nil {
			return err
		}
		fmt.Println("unshared")
		time.Sleep(after)
		return nil
	case fetch != "":
		raw, err := hex.DecodeString(fetch)
		var mcid manifest.Mcid
		if err != nil || len(raw) != len(mcid) {
			return fmt.Errorf("-fetch: not a 50-byte content id")
		}
		copy(mcid[:], raw)
		start := time.Now()
		data, err := pl.GetContent(ctx, realm, mcid, pool.ContentOptions{})
		took := time.Since(start).Round(time.Millisecond)
		if errors.Is(err, pool.ErrNotShared) {
			fmt.Printf("not_shared in %s: %v\n", took, err)
			return nil
		}
		if err != nil {
			return fmt.Errorf("fetch after %s: %w", took, err)
		}
		fmt.Printf("fetched %d bytes sha384 %s in %s\n", len(data), sum(data), took)
		return nil
	}
	return errors.New("give -share or -fetch")
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func sum(b []byte) string {
	h := sha512.Sum384(b)
	return hex.EncodeToString(h[:])
}

func decode32(s string, out *[32]byte) error {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return errors.New("not 64 hex characters")
	}
	copy(out[:], b)
	return nil
}
