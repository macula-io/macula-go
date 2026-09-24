package manifest

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

// erlangManifests is what scripts/interop/emit_erlang_manifest.escript wrote
// from macula's own macula_manifest.
type erlangManifests struct {
	Manifests []struct {
		Name        string   `json:"name"`
		Size        int      `json:"size"`
		ChunkSize   int      `json:"chunk_size"`
		McidHex     string   `json:"mcid_hex"`
		RootHex     string   `json:"root_hex"`
		ChunkHashes []string `json:"chunk_hashes"`
		ChunkMcids  []string `json:"chunk_mcids"`
		WireHex     string   `json:"wire_hex"`
	} `json:"manifests"`
	Block struct {
		DataHex string `json:"data_hex"`
		McidHex string `json:"mcid_hex"`
	} `json:"block"`
}

func pattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i % 251)
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// macula-go builds each manifest macula builds, byte for byte: its MCID, root
// hash, chunk hashes and chunk MCIDs, and the manifest as a CALL payload
// carries it; it reads macula's wire form back to the same manifest, and a
// single block's MCID is macula's.
func TestManifestsMatchMaculasByteForByte(t *testing.T) {
	raw, err := os.ReadFile("testdata/erlang_manifests.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var fixture erlangManifests
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	for _, want := range fixture.Manifests {
		name := string(unhex(t, want.Name))
		t.Run(name, func(t *testing.T) {
			m, chunks := createWithCreated(pattern(want.Size), CreateOptions{Name: name, ChunkSize: want.ChunkSize}, 1789000000)
			if hex.EncodeToString(m.Mcid[:]) != want.McidHex {
				t.Errorf("mcid %x, macula's %s", m.Mcid, want.McidHex)
			}
			if hex.EncodeToString(m.RootHash[:]) != want.RootHex {
				t.Errorf("root %x, macula's %s", m.RootHash, want.RootHex)
			}
			if len(chunks) != len(want.ChunkHashes) || len(m.Chunks) != len(want.ChunkHashes) {
				t.Fatalf("%d chunks, macula's %d", len(m.Chunks), len(want.ChunkHashes))
			}
			for i, c := range m.Chunks {
				mcid, _ := ChunkMcid(m, i)
				if hex.EncodeToString(c.Hash[:]) != want.ChunkHashes[i] || hex.EncodeToString(mcid[:]) != want.ChunkMcids[i] {
					t.Errorf("chunk %d: hash %x, mcid %x", i, c.Hash, mcid)
				}
			}
			wire := unhex(t, want.WireHex)
			if got := cbor.Encode(ToWire(m)); !bytes.Equal(got, wire) {
				t.Errorf("wire form differs from macula's:\n go     %x\n macula %x", got, wire)
			}
			decoded, err := cbor.Decode(wire)
			if err != nil {
				t.Fatalf("decode macula's wire form: %v", err)
			}
			read, err := FromWire(decoded)
			if err != nil {
				t.Fatalf("FromWire macula's manifest: %v", err)
			}
			if err := VerifyMcid(read, read.Mcid); err != nil || read.Mcid != m.Mcid {
				t.Errorf("macula's manifest read back: mcid %x, %v", read.Mcid, err)
			}
		})
	}
	block := BlockMcid(unhex(t, fixture.Block.DataHex))
	if hex.EncodeToString(block[:]) != fixture.Block.McidHex {
		t.Errorf("block mcid %x, macula's %s", block, fixture.Block.McidHex)
	}
}
