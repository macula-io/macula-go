package pool

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
)

var contentRealm = [32]byte{0x0c}

// contentPools are a sharer on one station and a fetcher on another sharing
// its DHT, neither trusting any realm.
func contentPools(t *testing.T, name string) (*Pool, *Pool, *teststation.Station, *teststation.Station) {
	t.Helper()
	sharing := teststation.Start(t, profile.PQPure, name+" sharing")
	fetching := teststation.Start(t, profile.PQPure, name+" fetching")
	teststation.ShareDHT(sharing, fetching)
	untrusting := func(o *Opts) { o.RealmTrust = nil }
	sharer := connectWith(t, name+" sharer", teststation.Realm{}, untrusting, sharing)
	fetcher := connectWith(t, name+" fetcher", teststation.Realm{}, untrusting, fetching)
	return sharer, fetcher, sharing, fetching
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// One raw block, a chunked blob, and a fetch after unsharing, from a sharer on
// another station, dialed through that station's own endpoint record.
func TestContentIsFetchedFromTheNodeThatSharesIt(t *testing.T) {
	sharer, fetcher, sharing, _ := contentPools(t, "content")
	ctx := t.Context()
	for _, c := range []struct {
		name string
		data []byte
	}{{"a raw block", pattern(10_000)}, {"a chunked blob", pattern(600_000)}} {
		t.Run(c.name, func(t *testing.T) {
			mcid, err := sharer.ShareContent(ctx, contentRealm, c.data, "blob.bin")
			if err != nil {
				t.Fatalf("ShareContent: %v", err)
			}
			if chunked := manifest.McidIsChunked(mcid); chunked != (len(c.data) > manifest.DefaultChunkSize) {
				t.Errorf("chunked %v for %d bytes", chunked, len(c.data))
			}
			got, err := fetcher.GetContent(ctx, contentRealm, mcid, ContentOptions{})
			if err != nil || !bytes.Equal(got, c.data) {
				t.Fatalf("GetContent: %d bytes, %v", len(got), err)
			}
			if !sharing.Connected(fetcher.NodeID()) {
				t.Error("the fetcher did not dial the sharer's station")
			}
			if err := sharer.UnshareContent(ctx, contentRealm, mcid); err != nil {
				t.Fatalf("UnshareContent: %v", err)
			}
			if _, err := fetcher.GetContent(ctx, contentRealm, mcid, ContentOptions{}); !errors.Is(err, ErrNotShared) {
				t.Errorf("after unsharing: %v, want ErrNotShared", err)
			}
		})
	}
	if _, err := fetcher.GetContent(ctx, [32]byte{0x0d}, manifest.BlockMcid([]byte("never shared")), ContentOptions{}); !errors.Is(err, ErrNotShared) {
		t.Errorf("content nobody shares: %v, want ErrNotShared", err)
	}
}

// Content over the fetch's bounds is refused before any chunk is asked for.
func TestAFetchRefusesContentOverItsBounds(t *testing.T) {
	sharer, fetcher, _, _ := contentPools(t, "bounds")
	mcid, err := sharer.ShareContent(t.Context(), contentRealm, pattern(600_000), "big.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.GetContent(t.Context(), contentRealm, mcid, ContentOptions{MaxBytes: 500_000}); !errors.Is(err, ErrContentTooLarge) {
		t.Errorf("a manifest over MaxBytes: %v, want ErrContentTooLarge", err)
	}
	if _, err := fetcher.GetContent(t.Context(), contentRealm, mcid, ContentOptions{MaxChunks: 2}); !errors.Is(err, ErrContentTooLarge) {
		t.Errorf("a manifest over MaxChunks: %v, want ErrContentTooLarge", err)
	}
}

// A sharer that answers with bytes that are not the content is refused; an
// announcement pointing at another node's procedure is never tried.
func TestNothingASharerSaysIsTrusted(t *testing.T) {
	_, fetcher, sharing, _ := contentPools(t, "liar")
	liar := connectWith(t, "liar", teststation.Realm{}, func(o *Opts) { o.RealmTrust = nil }, sharing)
	asked := []byte("the content asked for")
	mcid := manifest.BlockMcid(asked)
	lie := cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text("block")},
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}, {Key: cbor.Text("bytes"), Val: cbor.Bytes([]byte("something else"))}})
	own := record.OwnProcedure(liar.NodeID(), ContentProcedureName)
	if _, err := liar.Serve(t.Context(), Offer{Realm: contentRealm, Procedure: own, Stream: &stationlink.StreamOffer{
		Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			if err := s.SendValue(lie); err != nil {
				return err
			}
			return s.Close()
		}}}); err != nil {
		t.Fatal(err)
	}
	announce := func(procedure string) {
		unsigned, err := record.NewContentAnnouncement(liar.NodeID(), mcid[:], record.ContentAnnouncementOptions{
			RealmID: contentRealm, ServingStation: sharing.NodeID, Procedure: procedure})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := record.Sign(unsigned, liar.key)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := record.Encode(signed)
		if err != nil {
			t.Fatal(err)
		}
		if err := liar.PutRecord(t.Context(), wire); err != nil {
			t.Fatal(err)
		}
	}
	announce(record.OwnProcedure(fetcher.NodeID(), ContentProcedureName))
	if _, err := fetcher.GetContent(t.Context(), contentRealm, mcid, ContentOptions{}); !errors.Is(err, ErrNotShared) {
		t.Errorf("an announcement pointing at another node's procedure: %v, want ErrNotShared", err)
	}
	announce(own)
	_, err := fetcher.GetContent(t.Context(), contentRealm, mcid, ContentOptions{})
	if !errors.Is(err, ErrContentUnavailable) || !errors.Is(err, ErrContentMismatch) {
		t.Errorf("a sharer answering with other bytes: %v, want ErrContentUnavailable and ErrContentMismatch", err)
	}
}

func TestAContentProcedureIsBoundToItsAnnouncer(t *testing.T) {
	node := [32]byte{0xab}
	hexNode := "ab" + strings.Repeat("00", 31)
	for procedure, want := range map[string]bool{
		"~" + hexNode + "/content_v1":                  true,
		"acme/content_v1_" + hexNode:                   true,
		"~" + strings.ToUpper(hexNode) + "/content_v1": false,
		"~" + hexNode + "/content_v2":                  false,
		"acme/content_v1_" + strings.Repeat("cd", 32):  false,
		"/content_v1_" + hexNode:                       false,
		"_/content_v1_" + hexNode:                      false,
		"~x/content_v1_" + hexNode:                     false,
		"acme/sub/content_v1_" + hexNode:               false,
	} {
		if got := ContentProcedureBound(procedure, node); got != want {
			t.Errorf("%q bound: %v, want %v", procedure, got, want)
		}
	}
}

// A sharer's announcement names where it is served, and a fetch runs on
// streams that are all released.
func TestAnAnnouncementNamesWhereTheContentIsServed(t *testing.T) {
	sharer, fetcher, sharing, fetching := contentPools(t, "announce")
	mcid, err := sharer.ShareContent(t.Context(), contentRealm, pattern(300_000), "two.bin")
	if err != nil {
		t.Fatal(err)
	}
	key, _ := record.ContentKey(mcid[:])
	found, _, err := fetcher.FindRecords(t.Context(), key)
	if err != nil || len(found) != 1 {
		t.Fatalf("announcements: %d, %v", len(found), err)
	}
	a, _ := record.ReadContentAnnouncement(found[0].Record())
	if a.AnnouncerNode != sharer.NodeID() || a.RealmID != contentRealm || a.ServingStation != sharing.NodeID ||
		a.Procedure != record.OwnProcedure(sharer.NodeID(), ContentProcedureName) || a.ChunkCount == nil || *a.ChunkCount != 2 {
		t.Errorf("announcement %+v", a)
	}
	if _, err := fetcher.GetContent(t.Context(), contentRealm, mcid, ContentOptions{Parallel: 1}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "every content stream released", func() bool { return sharing.Relayed() == 0 && fetching.Relayed() == 0 })
}

// liarFor serves, on its own content procedure, whatever answer gives for a
// fetch's want and content id, and announces mcid as shared there.
func liarFor(t *testing.T, name string, station *teststation.Station, mcid manifest.Mcid,
	answer func(want string, asked []byte) cbor.Value) {
	t.Helper()
	liar := connectWith(t, name, teststation.Realm{}, func(o *Opts) { o.RealmTrust = nil }, station)
	own := record.OwnProcedure(liar.NodeID(), ContentProcedureName)
	if _, err := liar.Serve(t.Context(), Offer{Realm: contentRealm, Procedure: own, Stream: &stationlink.StreamOffer{
		Mode: frame.ServerStream, Handler: func(_ context.Context, s *stationlink.Stream) error {
			want, _ := wireText(s.Request().Payload, "want")
			asked, _ := wireBytes(s.Request().Payload, "mcid")
			if err := s.SendValue(answer(want, asked)); err != nil {
				return err
			}
			return s.Close()
		}}}); err != nil {
		t.Fatal(err)
	}
	unsigned, err := record.NewContentAnnouncement(liar.NodeID(), mcid[:], record.ContentAnnouncementOptions{
		RealmID: contentRealm, ServingStation: station.NodeID, Procedure: own})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := record.Sign(unsigned, liar.key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := liar.PutRecord(t.Context(), wire); err != nil {
		t.Fatal(err)
	}
}

func blockBody(mcid, b []byte) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text("block")},
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid)}, {Key: cbor.Text("bytes"), Val: cbor.Bytes(b)}})
}

func manifestBody(mcid manifest.Mcid, m manifest.Manifest) cbor.Value {
	return cbor.Map([]cbor.MapEntry{{Key: cbor.Text("kind"), Val: cbor.Text("manifest")},
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(mcid[:])}, {Key: cbor.Text("manifest"), Val: manifest.ToWire(m)}})
}

// A manifest must match the content id before anything it says is used, and
// every chunk its own content id, before the whole is assembled.
func TestAManifestAndItsChunksAreCheckedAgainstTheirContentIDs(t *testing.T) {
	_, fetcher, sharing, _ := contentPools(t, "manifests")
	real, realChunks := manifest.Create(pattern(600_000), manifest.CreateOptions{Name: "real.bin", ChunkSize: manifest.DefaultChunkSize})
	other, otherChunks := manifest.Create(pattern(700_000)[100_000:], manifest.CreateOptions{Name: "other.bin", ChunkSize: manifest.DefaultChunkSize})
	chunkOf := func(m manifest.Manifest, chunks [][]byte, asked []byte) []byte {
		for i := range chunks {
			if c, _ := manifest.ChunkMcid(m, i); string(c[:]) == string(asked) {
				return chunks[i]
			}
		}
		return nil
	}
	liarFor(t, "manifest liar", sharing, real.Mcid, func(want string, asked []byte) cbor.Value {
		if want == "root" {
			return manifestBody(real.Mcid, other)
		}
		return blockBody(asked, chunkOf(other, otherChunks, asked))
	})
	_, err := fetcher.GetContent(t.Context(), contentRealm, real.Mcid, ContentOptions{})
	if !errors.Is(err, ErrContentMismatch) || !errors.Is(err, manifest.ErrManifestMcidMismatch) {
		t.Errorf("another content's manifest: %v, want ErrContentMismatch for the manifest", err)
	}

	var chunksAsked atomic.Int32
	liarFor(t, "chunk liar", sharing, real.Mcid, func(want string, asked []byte) cbor.Value {
		if want == "root" {
			return manifestBody(real.Mcid, real)
		}
		chunksAsked.Add(1)
		b := append([]byte(nil), chunkOf(real, realChunks, asked)...)
		b[0] ^= 0xff
		return blockBody(asked, b)
	})
	_, err = fetcher.GetContent(t.Context(), contentRealm, real.Mcid, ContentOptions{Parallel: 1})
	if !errors.Is(err, ErrContentMismatch) || !strings.Contains(err.Error(), "chunk") {
		t.Errorf("a chunk that is not its content id's: %v, want ErrContentMismatch for the chunk", err)
	}
	// Every chunk of this liar is bad: the first one ends the fetch, before
	// another is asked for.
	if n := chunksAsked.Load(); n != 1 {
		t.Errorf("%d chunks asked for after the first did not match, want 1", n)
	}
}

// Content shared in one realm is not found by a fetch in another.
func TestContentIsFetchedOnlyInTheRealmItIsSharedIn(t *testing.T) {
	sharer, fetcher, _, _ := contentPools(t, "realms")
	mcid, err := sharer.ShareContent(t.Context(), contentRealm, pattern(1_000), "r.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fetcher.GetContent(t.Context(), [32]byte{0x0d}, mcid, ContentOptions{}); !errors.Is(err, ErrNotShared) {
		t.Errorf("a fetch in another realm: %v, want ErrNotShared", err)
	}
}
