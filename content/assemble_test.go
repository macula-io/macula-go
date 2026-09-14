package content

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/manifest"
)

// chunkedContent is three chunks of content filled from seed, with its
// manifest and its blocks by MCID.
func chunkedContent(seed int) (manifest.Manifest, map[manifest.Mcid][]byte, []byte) {
	data := make([]byte, 3*manifest.DefaultChunkSize-1)
	for i := range data {
		data[i] = byte(i % seed)
	}
	m, chunks := manifest.Create(data, manifest.DefaultCreateOptions())
	blocks := make(map[manifest.Mcid][]byte, len(chunks))
	for i, chunk := range chunks {
		chunkMcid, _ := manifest.ChunkMcid(m, i)
		blocks[chunkMcid] = chunk
	}
	return m, blocks, data
}

// servedBy fetches a block from blocks, counting each fetch in fetched.
func servedBy(blocks map[manifest.Mcid][]byte, fetched *int) func(manifest.Mcid) ([]byte, error) {
	return func(mcid manifest.Mcid) ([]byte, error) {
		*fetched++
		if block, ok := blocks[mcid]; ok {
			return block, nil
		}
		return nil, ErrNotFound
	}
}

// assembled is assemble, with a panic turned into a test failure.
func assembled(t *testing.T, mcid manifest.Mcid, m manifest.Manifest, fetchBlock func(manifest.Mcid) ([]byte, error)) ([]byte, error) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("assembling the content panicked: %v", r)
		}
	}()
	return assemble(mcid, m, fetchBlock)
}

// A manifest whose chunk hashes don't combine to its root hash is refused
// before any chunk is fetched, even though it describes the MCID asked for:
// the chunk hashes are not part of the MCID, the root hash is.
func TestGetRefusesAManifestWhoseChunkHashesDoNotMakeItsRootHash(t *testing.T) {
	m, blocks, _ := chunkedContent(251)
	m.Chunks[1].Hash[0] ^= 1
	fetched := 0
	_, err := assembled(t, m.Mcid, m, servedBy(blocks, &fetched))
	if !errors.Is(err, ErrHashMismatch) || fetched != 0 {
		t.Fatalf("err %v after %d fetches, want ErrHashMismatch and no fetch", err, fetched)
	}
}

func TestGetAssemblesTheContentAWholeManifestForItsMcidDescribes(t *testing.T) {
	m, blocks, data := chunkedContent(251)
	fetched := 0
	got, err := assembled(t, m.Mcid, m, servedBy(blocks, &fetched))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("assembled %d bytes (err %v), want the %d bytes the manifest describes", len(got), err, len(data))
	}
}

// A manifest that doesn't describe the MCID asked for is refused before any
// chunk is fetched, even one that is consistent with its own chunks.
func TestGetRefusesAManifestThatDoesNotDescribeTheRequestedMcid(t *testing.T) {
	requested, _, _ := chunkedContent(251)
	substitute, blocks, _ := chunkedContent(241)
	fetched := 0
	got, err := assembled(t, requested.Mcid, substitute, servedBy(blocks, &fetched))
	if !errors.Is(err, ErrHashMismatch) || !errors.Is(err, manifest.ErrManifestMcidMismatch) || got != nil || fetched != 0 {
		t.Fatalf("a substituted manifest gave %d bytes and err %v after %d fetches, want ErrHashMismatch, no content and no fetch", len(got), err, fetched)
	}
}

// A manifest for its own MCID that counts more chunks than it lists is
// refused as not whole.
func TestGetRefusesAManifestCountingMoreChunksThanItLists(t *testing.T) {
	m, blocks, _ := chunkedContent(251)
	m.ChunkCount += 5
	m.Mcid = manifest.McidFor(m)
	fetched := 0
	got, err := assembled(t, m.Mcid, m, servedBy(blocks, &fetched))
	if !errors.Is(err, manifest.ErrManifestNotWhole) || got != nil {
		t.Fatalf("a manifest counting 5 chunks it doesn't list gave %d bytes and err %v, want ErrManifestNotWhole", len(got), err)
	}
}

// A manifest for its own MCID that claims more bytes than its chunks hold is
// refused as not whole, before anything is sized from its claim.
func TestGetRefusesAManifestClaimingMoreBytesThanItsChunksHold(t *testing.T) {
	m, blocks, _ := chunkedContent(251)
	m.Size = 1 << 62
	m.Mcid = manifest.McidFor(m)
	fetched := 0
	got, err := assembled(t, m.Mcid, m, servedBy(blocks, &fetched))
	if !errors.Is(err, manifest.ErrManifestNotWhole) || got != nil {
		t.Fatalf("a manifest claiming 2^62 bytes gave %d bytes and err %v, want ErrManifestNotWhole", len(got), err)
	}
}

// A manifest for its own MCID with a chunk size of zero is refused as not
// whole, before its content is re-chunked by that size.
func TestGetRefusesAManifestWithAChunkSizeOfZero(t *testing.T) {
	m, blocks, _ := chunkedContent(251)
	m.ChunkSize = 0
	m.Mcid = manifest.McidFor(m)
	fetched := 0
	got, err := assembled(t, m.Mcid, m, servedBy(blocks, &fetched))
	if !errors.Is(err, manifest.ErrManifestNotWhole) || got != nil || fetched != 0 {
		t.Fatalf("a manifest with chunk size 0 gave %d bytes and err %v after %d fetches, want ErrManifestNotWhole and no fetch", len(got), err, fetched)
	}
}
