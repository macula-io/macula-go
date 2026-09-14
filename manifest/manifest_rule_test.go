package manifest

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// emptyRootHash is BLAKE3 of no bytes, the root hash of empty content in every
// macula stack.
const emptyRootHash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"

// wireWithAlgorithm is m's wire form with its hash_algorithm set to value.
func wireWithAlgorithm(m Manifest, value cbor.Value) cbor.Value {
	entries, _ := ToWire(m).AsMap()
	out := make([]cbor.MapEntry, 0, len(entries)+1)
	for _, e := range entries {
		if key, _ := e.Key.AsText(); key != "hash_algorithm" {
			out = append(out, e)
		}
	}
	return cbor.Map(append(out, cbor.MapEntry{Key: cbor.Text("hash_algorithm"), Val: value}))
}

// A manifest naming sha256 is refused where it is read, as text or as bytes:
// every chunk fetch checks BLAKE3, so blake3 is the one algorithm accepted.
func TestASha256ManifestIsRefused(t *testing.T) {
	m := threeChunks()
	for _, value := range []cbor.Value{cbor.Text("sha256"), cbor.Bytes([]byte("sha256"))} {
		if _, err := FromWire(wireWithAlgorithm(m, value)); err == nil {
			t.Errorf("FromWire accepted hash_algorithm %v", value)
		}
	}
}

// VerifyMcid refuses a manifest naming sha256, even for the MCID its own
// fields describe.
func TestVerifyMcidRefusesSha256(t *testing.T) {
	// Algorithm(1) was Sha256, the one other algorithm a manifest could name.
	sha, shaMcid := withOwnMcid(edited(threeChunks(), func(c *Manifest) { c.HashAlgorithm = Algorithm(1) }))
	if err := VerifyMcid(sha, shaMcid); !errors.Is(err, ErrManifestMcidMismatch) {
		t.Errorf("VerifyMcid = %v, want %v", err, ErrManifestMcidMismatch)
	}
}

// Empty content has one whole form: size 0, chunk_count 0, no chunks, a
// positive chunk_size and BLAKE3 of no bytes as its root hash. That form reads
// back, describes its MCID and verifies; the same content as one empty chunk
// is refused where it is read.
func TestEmptyContentHasOneWholeForm(t *testing.T) {
	empty, _ := Create(nil, DefaultCreateOptions())
	back, err := FromWire(ToWire(empty))
	if err != nil {
		t.Fatalf("FromWire of empty content as created: %v", err)
	}
	if back.Size != 0 || back.ChunkCount != 0 || len(back.Chunks) != 0 || back.ChunkSize <= 0 {
		t.Errorf("empty content read back as size %d, chunk_count %d, %d chunks, chunk_size %d",
			back.Size, back.ChunkCount, len(back.Chunks), back.ChunkSize)
	}
	if got := hex.EncodeToString(back.RootHash[:]); got != emptyRootHash {
		t.Errorf("empty content's root hash = %s, want %s", got, emptyRootHash)
	}
	if err := VerifyMcid(back, empty.Mcid); err != nil {
		t.Errorf("VerifyMcid of empty content: %v", err)
	}
	if err := Verify(back, nil); err != nil {
		t.Errorf("Verify of empty content: %v", err)
	}
	oneEmptyChunk := edited(empty, func(c *Manifest) {
		c.ChunkCount = 1
		c.Chunks = []ChunkInfo{{Index: 0, Offset: 0, Size: 0, Hash: c.RootHash}}
	})
	if _, err := FromWire(ToWire(oneEmptyChunk)); !errors.Is(err, ErrManifestNotWhole) {
		t.Errorf("FromWire of empty content as one empty chunk = %v, want %v", err, ErrManifestNotWhole)
	}
}

// A chunk of no bytes is not whole, and a manifest listing one is refused
// where it is read.
func TestAnEmptyChunkIsNotWhole(t *testing.T) {
	m := edited(threeChunks(), func(c *Manifest) { c.Chunks[2].Size = 0 })
	if err := CheckWhole(m); !errors.Is(err, ErrManifestNotWhole) {
		t.Errorf("CheckWhole = %v, want %v", err, ErrManifestNotWhole)
	}
	if _, err := FromWire(ToWire(m)); !errors.Is(err, ErrManifestNotWhole) {
		t.Errorf("FromWire = %v, want %v", err, ErrManifestNotWhole)
	}
}
