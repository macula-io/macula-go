package manifest

import (
	"bytes"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

func threeChunks() Manifest {
	m, _ := Create(bytes.Repeat([]byte{1}, 2*DefaultChunkSize+3), DefaultCreateOptions())
	return m
}

// edited is a copy of m, with its own chunk list, changed by change.
func edited(m Manifest, change func(*Manifest)) Manifest {
	c := m
	c.Chunks = append([]ChunkInfo(nil), m.Chunks...)
	change(&c)
	return c
}

// withOwnMcid is m with its Mcid recomputed from its canonical fields.
func withOwnMcid(m Manifest) (Manifest, Mcid) {
	m.Mcid = McidFor(m)
	return m, m.Mcid
}

// VerifyMcid checks the fields macula_manifest's verify_mcid/2 checks and no
// others: the canonical fields must recompute to the MCID, the name must be
// UTF-8 and the algorithm known.
func TestVerifyMcidChecksTheFieldsMaculaChecks(t *testing.T) {
	m := threeChunks()
	notUTF8, notUTF8Mcid := withOwnMcid(edited(m, func(c *Manifest) { c.Name = "\xff\xfe" }))
	unknown, unknownMcid := withOwnMcid(edited(m, func(c *Manifest) { c.HashAlgorithm = Algorithm(7) }))
	cases := []struct {
		name     string
		manifest Manifest
		mcid     Mcid
		want     error
	}{
		{"as created", m, m.Mcid, nil},
		{"another created time, version, own mcid and chunk list", edited(m, func(c *Manifest) { c.Created++; c.Version = 9; c.Mcid = Mcid{}; c.Chunks = nil }), m.Mcid, nil},
		{"another name", edited(m, func(c *Manifest) { c.Name = "other" }), m.Mcid, ErrManifestMcidMismatch},
		{"another size", edited(m, func(c *Manifest) { c.Size++ }), m.Mcid, ErrManifestMcidMismatch},
		{"another chunk count", edited(m, func(c *Manifest) { c.ChunkCount++ }), m.Mcid, ErrManifestMcidMismatch},
		{"another root hash", edited(m, func(c *Manifest) { c.RootHash[0] ^= 1 }), m.Mcid, ErrManifestMcidMismatch},
		{"a name that isn't UTF-8, for its own MCID", notUTF8, notUTF8Mcid, ErrManifestMcidMismatch},
		{"an unknown hash algorithm, for its own MCID", unknown, unknownMcid, ErrManifestMcidMismatch},
	}
	for _, tc := range cases {
		if err := VerifyMcid(tc.manifest, tc.mcid); !errors.Is(err, tc.want) {
			t.Errorf("%s: VerifyMcid = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestCheckWholeRefusesChunksThatDoNotDescribeTheContentWhole(t *testing.T) {
	m := threeChunks()
	cases := []struct {
		name     string
		manifest Manifest
		whole    bool
	}{
		{"as created", m, true},
		{"a chunk counted that isn't listed", edited(m, func(c *Manifest) { c.ChunkCount++ }), false},
		{"chunks out of index order", edited(m, func(c *Manifest) { c.Chunks[0].Index, c.Chunks[1].Index = 1, 0 }), false},
		{"a gap between chunks", edited(m, func(c *Manifest) { c.Chunks[1].Offset++ }), false},
		{"an empty chunk", edited(m, func(c *Manifest) { c.Chunks[2].Size = 0 }), false},
		{"a chunk larger than the chunk size", edited(m, func(c *Manifest) { c.Chunks[2].Size = c.ChunkSize + 1 }), false},
		{"a size the chunks don't add up to", edited(m, func(c *Manifest) { c.Size++ }), false},
		{"a chunk size of zero", edited(m, func(c *Manifest) { c.ChunkSize = 0 }), false},
		{"a negative chunk size", edited(m, func(c *Manifest) { c.ChunkSize = -1 }), false},
	}
	for _, tc := range cases {
		err := CheckWhole(tc.manifest)
		if tc.whole != (err == nil) || (err != nil && !errors.Is(err, ErrManifestNotWhole)) {
			t.Errorf("%s: CheckWhole = %v, want whole %v", tc.name, err, tc.whole)
		}
	}
}

// Verify refuses a manifest whose chunk size isn't positive instead of
// re-chunking the data by it.
func TestVerifyRefusesAChunkSizeThatIsNotPositive(t *testing.T) {
	if err := Verify(Manifest{ChunkSize: 0, Size: 1}, []byte{1}); err == nil {
		t.Fatal("Verify accepted a chunk size of 0")
	}
}

// FromWire reads hash_algorithm as macula_manifest's from_wire/1 does: a
// missing one is blake3, a known name as text or bytes is that algorithm,
// and an unknown one is refused.
func TestFromWireReadsTheHashAlgorithmAsMaculaDoes(t *testing.T) {
	m, _ := Create([]byte("some content"), DefaultCreateOptions())
	wire, _ := ToWire(m).AsMap()
	with := func(value *cbor.Value) cbor.Value {
		out := make([]cbor.MapEntry, 0, len(wire))
		for _, e := range wire {
			if key, _ := e.Key.AsText(); key != "hash_algorithm" {
				out = append(out, e)
			}
		}
		if value != nil {
			out = append(out, cbor.MapEntry{Key: cbor.Text("hash_algorithm"), Val: *value})
		}
		return cbor.Map(out)
	}
	text, raw, unknown := cbor.Text("sha256"), cbor.Bytes([]byte("sha256")), cbor.Text("md5")
	cases := []struct {
		name  string
		value *cbor.Value
		want  Algorithm
		ok    bool
	}{
		{"missing", nil, Blake3, true},
		{"sha256 as text", &text, Sha256, true},
		{"sha256 as bytes", &raw, Sha256, true},
		{"an unknown name", &unknown, Blake3, false},
	}
	for _, tc := range cases {
		got, err := FromWire(with(tc.value))
		if tc.ok != (err == nil) || (err == nil && got.HashAlgorithm != tc.want) {
			t.Errorf("%s: FromWire algorithm %v, err %v; want %v, ok %v", tc.name, got.HashAlgorithm, err, tc.want, tc.ok)
		}
	}
}
