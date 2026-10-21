// Command gocontent shares or fetches node-served content (macula 12.6.0,
// D27) through one station, for the cross-check against macula's Erlang
// sharer and fetcher (see scripts/interop/README.md).
//
//	gocontent -host 127.0.0.1 -port 44330 -node <station node_id> -realm <hex> -share 600000 -hold 2m
//	gocontent -host 127.0.0.1 -port 44330 -node <station node_id> -realm <hex> -fetch <mcid hex>
//	gocontent -host 127.0.0.1 -port 44330 -node <station node_id> -realm <hex> -share 600000 -pad-chunk -hold 1m
//
// -pad-chunk shares as a dishonest sharer would: the true manifest, but its
// first chunk answered one byte past its declared size, which a fetcher must
// refuse.
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

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
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
	padChunk := flag.Bool("pad-chunk", false, "with -share: answer the first chunk one byte past its declared size")
	flag.Parse()
	if err := run(*host, *port, *node, *profileName, *realmHex, *share, *hold, *after, *fetch, *padChunk); err != nil {
		fmt.Fprintln(os.Stderr, "gocontent:", err)
		os.Exit(1)
	}
}

func run(host string, port int, nodeHex, profileName, realmHex string, share int, hold, after time.Duration, fetch string, padChunk bool) error {
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
	case share >= 0 && padChunk:
		return sharePadded(ctx, pl, key, realm, station, pattern(share), hold)
	case share >= 0:
		return shareContent(ctx, pl, realm, pattern(share), hold, after)
	case fetch != "":
		return fetchContent(ctx, pl, realm, fetch)
	}
	return errors.New("give -share or -fetch")
}

// shareContent shares data for hold, then unshares it and stays linked for
// after.
func shareContent(ctx context.Context, pl *pool.Pool, realm [32]byte, data []byte, hold, after time.Duration) error {
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
}

// fetchContent fetches the content one MCID names and reports what came back.
func fetchContent(ctx context.Context, pl *pool.Pool, realm [32]byte, fetch string) error {
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

// sharePadded serves data's true manifest on this node's content procedure,
// but answers its first chunk with one byte appended, and announces it.
func sharePadded(ctx context.Context, pl *pool.Pool, key *identity.NodeKey, realm, station [32]byte, data []byte, hold time.Duration) error {
	m, chunks := manifest.Create(data, manifest.CreateOptions{Name: "padded.bin", ChunkSize: manifest.DefaultChunkSize})
	if len(chunks) < 2 {
		return errors.New("-pad-chunk needs content over one chunk")
	}
	procedure := record.OwnProcedure(pl.NodeID(), pool.ContentProcedureName)
	if _, err := pl.Serve(ctx, pool.Offer{Realm: realm, Procedure: procedure, Stream: &stationlink.StreamOffer{
		Mode: frame.ServerStream, Handler: paddedHandler(m, paddedChunks(m, chunks))}}); err != nil {
		return err
	}
	if err := announceContent(ctx, pl, key, realm, station, procedure, m); err != nil {
		return err
	}
	fmt.Printf("shared %s %d bytes padded-first-chunk\n", hex.EncodeToString(m.Mcid[:]), len(data))
	time.Sleep(hold)
	return nil
}

// paddedChunks is the chunks by their content id, the first one a byte past
// its declared size.
func paddedChunks(m manifest.Manifest, chunks [][]byte) map[string][]byte {
	byMcid := map[string][]byte{}
	for i, c := range chunks {
		chunkMcid, _ := manifest.ChunkMcid(m, i)
		byMcid[string(chunkMcid[:])] = c
	}
	first, _ := manifest.ChunkMcid(m, 0)
	byMcid[string(first[:])] = append(append([]byte(nil), chunks[0]...), 0)
	return byMcid
}

// paddedHandler answers the manifest and the chunks it names, the first chunk
// with its byte appended.
func paddedHandler(m manifest.Manifest, byMcid map[string][]byte) func(context.Context, *stationlink.Stream) error {
	body := func(kind string, mcid []byte, entry cbor.MapEntry) cbor.Value {
		return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text(kind)},
			{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid)}, entry})
	}
	return func(_ context.Context, s *stationlink.Stream) error {
		asked, _ := s.Request().Payload.Get("mcid")
		mcid, _ := asked.AsBytes()
		if string(mcid) == string(m.Mcid[:]) {
			if err := s.SendValue(body("manifest", mcid, cbor.MapEntry{Key: cbor.Text("manifest"), Val: manifest.ToWire(m)})); err != nil {
				return err
			}
			return s.Close()
		}
		chunk, held := byMcid[string(mcid)]
		if !held {
			return s.Abort("not_shared", "this node does not share that content")
		}
		if err := s.SendValue(body("block", mcid, cbor.MapEntry{Key: cbor.Text("bytes"), Val: cbor.Bytes(chunk)})); err != nil {
			return err
		}
		return s.Close()
	}
}

// announceContent puts the content announcement that says this node serves
// the manifest.
func announceContent(ctx context.Context, pl *pool.Pool, key *identity.NodeKey, realm, station [32]byte,
	procedure string, m manifest.Manifest) error {
	unsigned, err := record.NewContentAnnouncement(pl.NodeID(), m.Mcid[:], record.ContentAnnouncementOptions{
		RealmID: realm, ServingStation: station, Procedure: procedure, TTLMs: uint64(time.Hour / time.Millisecond)})
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
	return pl.PutRecord(ctx, wire)
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
