package manifest

import (
	"bytes"
	"testing"
)

// A single block's MCID is tag 2, codec raw and the block's SHA-384.
func TestBlockMcidIsTheBlocksSHA384(t *testing.T) {
	data := []byte("small blob, single block")
	want := makeMcid(codecRaw, SHA384.hash(data))
	got := BlockMcid(data)
	if got != want {
		t.Fatalf("BlockMcid = %x, want %x", got, want)
	}
	if McidIsChunked(got) {
		t.Errorf("BlockMcid's own MCID reports as chunked")
	}
}

func TestCreateChunksExactBoundaryProducesNoEmptyTrailingChunk(t *testing.T) {
	data := bytes.Repeat([]byte{0x42}, 20)
	m, chunks := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 10}, 1000)
	if len(chunks) != 2 {
		t.Fatalf("len(chunks) = %d, want 2 (no empty trailing chunk on an exact boundary)", len(chunks))
	}
	if m.ChunkCount != 2 {
		t.Errorf("m.ChunkCount = %d, want 2", m.ChunkCount)
	}
	if len(chunks[0]) != 10 || len(chunks[1]) != 10 {
		t.Errorf("chunk sizes = %d, %d, want 10, 10", len(chunks[0]), len(chunks[1]))
	}
}

func TestCreateChunksUnevenRemainder(t *testing.T) {
	data := bytes.Repeat([]byte{0x7}, 25)
	m, chunks := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 10}, 1000)
	if len(chunks) != 3 {
		t.Fatalf("len(chunks) = %d, want 3", len(chunks))
	}
	if len(chunks[2]) != 5 {
		t.Errorf("last chunk size = %d, want 5", len(chunks[2]))
	}
	if m.Size != 25 {
		t.Errorf("m.Size = %d, want 25", m.Size)
	}
}

func TestMcidIsChunkedDistinguishesSingleBlockFromManifest(t *testing.T) {
	data := bytes.Repeat([]byte{0x1}, 100)
	m, _ := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 10}, 1000)
	if !McidIsChunked(m.Mcid) {
		t.Errorf("a manifest's own MCID must report as chunked")
	}
	if McidIsChunked(BlockMcid(data)) {
		t.Errorf("a single-block MCID must not report as chunked")
	}
}

func TestChunkMcidIsTheBlockMcidOfTheChunk(t *testing.T) {
	data := bytes.Repeat([]byte{0x9}, 25)
	m, chunks := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 10}, 1000)
	for i, chunk := range chunks {
		got, ok := ChunkMcid(m, i)
		if !ok {
			t.Fatalf("ChunkMcid(%d) not ok", i)
		}
		// A chunk is stored and fetched as a block of its bytes, so its
		// address is the SHA-384 block MCID of those bytes.
		if want := BlockMcid(chunk); got != want {
			t.Errorf("ChunkMcid(%d) = %x, want %x", i, got, want)
		}
	}
	if _, ok := ChunkMcid(m, len(chunks)); ok {
		t.Errorf("ChunkMcid out of range returned ok=true")
	}
}

func TestRootHashOddLeafCountPairsLastHashWithItself(t *testing.T) {
	// 3 chunks -> combine() pairs (0,1) and folds 2 with itself.
	data := bytes.Repeat([]byte{0x3}, 25) // chunkSize 10 -> 3 chunks: 10,10,5
	m, _ := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 10}, 1000)

	infos := m.Chunks
	h0, h1, h2 := infos[0].Hash, infos[1].Hash, infos[2].Hash
	level1a := combineOne(h0, h1, SHA384)
	level1b := combineOne(h2, h2, SHA384) // odd one out, paired with itself
	want := combineOne(level1a, level1b, SHA384)
	if m.RootHash != want {
		t.Fatalf("RootHash = %x, want %x (manual odd-leaf fold)", m.RootHash, want)
	}
}

func combineOne(l, r Hash, alg Algorithm) Hash {
	buf := make([]byte, 0, 64)
	buf = append(buf, l[:]...)
	buf = append(buf, r[:]...)
	return alg.hash(buf)
}

func TestVerifyAcceptsReassembledDataAndRejectsTampering(t *testing.T) {
	data := bytes.Repeat([]byte{0x5}, 1000)
	m, _ := createWithCreated(data, CreateOptions{Name: "x", ChunkSize: 300}, 1000)

	if err := Verify(m, data); err != nil {
		t.Fatalf("Verify(original data) = %v, want nil", err)
	}

	tampered := bytes.Clone(data)
	tampered[500] ^= 0xFF
	if err := Verify(m, tampered); err == nil {
		t.Errorf("Verify(tampered data) = nil, want an error")
	}

	if err := Verify(m, data[:999]); err == nil {
		t.Errorf("Verify(wrong-size data) = nil, want an error")
	}
}

func TestToWireFromWireRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte{0x11, 0x22}, 500)
	m, _ := createWithCreated(data, CreateOptions{Name: "my-file.bin", ChunkSize: 300}, 1_700_000_000)

	wire := ToWire(m)
	back, err := FromWire(wire)
	if err != nil {
		t.Fatalf("FromWire: %v", err)
	}

	if back.Mcid != m.Mcid {
		t.Errorf("Mcid round-trip mismatch")
	}
	if back.Name != m.Name {
		t.Errorf("Name round-trip: got %q, want %q", back.Name, m.Name)
	}
	if back.Size != m.Size || back.Created != m.Created || back.ChunkSize != m.ChunkSize || back.ChunkCount != m.ChunkCount {
		t.Errorf("scalar field round-trip mismatch: %+v vs %+v", back, m)
	}
	if back.HashAlgorithm != m.HashAlgorithm {
		t.Errorf("HashAlgorithm round-trip: got %v, want %v", back.HashAlgorithm, m.HashAlgorithm)
	}
	if back.RootHash != m.RootHash {
		t.Errorf("RootHash round-trip mismatch")
	}
	if len(back.Chunks) != len(m.Chunks) {
		t.Fatalf("Chunks length round-trip: got %d, want %d", len(back.Chunks), len(m.Chunks))
	}
	for i := range m.Chunks {
		if back.Chunks[i] != m.Chunks[i] {
			t.Errorf("Chunks[%d] round-trip mismatch: got %+v, want %+v", i, back.Chunks[i], m.Chunks[i])
		}
	}
}

func TestNameWireEncodingIsBytesNotText(t *testing.T) {
	// ToWire's "name" field must be a raw byte string (major 2) -- NOT
	// text (major 3) -- distinct from computeMcid's internal, narrower
	// text-wrapped hash input. FromWire's own getStringBytes would fail
	// to parse a text-typed name, so a round trip through the real
	// accessor is the regression guard here.
	m, _ := createWithCreated([]byte("x"), CreateOptions{Name: "name-as-bytes", ChunkSize: 10}, 1)
	wire := ToWire(m)
	nameField, ok := wire.Get("name")
	if !ok {
		t.Fatalf("wire manifest missing \"name\" field")
	}
	if _, ok := nameField.AsBytes(); !ok {
		t.Errorf("wire manifest's \"name\" field is not bytes-typed")
	}
	if _, ok := nameField.AsText(); ok {
		t.Errorf("wire manifest's \"name\" field must not be text-typed")
	}
}
