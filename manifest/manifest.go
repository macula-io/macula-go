// Package manifest implements fixed-size chunking, Merkle-root
// computation, and manifest construction for content larger than one
// storage block — see plans/PLAN_WIRE_PROTOCOL.md §12.2. Mirrors the
// reference (and macula-rust-sdk's own port) byte-for-byte: same MCID
// format, same default chunk size (256 KiB), same Merkle fold
// (including the odd-leaf-count rule — pair the last hash with
// itself), same canonical-CBOR MCID derivation.
//
// Two different wire representations of name, both handled separately,
// not confused with each other: computeMcid's canonical hash input
// wraps name as CBOR text (a deliberate, narrow special case, just for
// that hash computation), while ToWire — the actual manifest map sent
// in a _content.put_manifest CALL payload — encodes name as a raw byte
// string, matching its binary() type.
package manifest

import (
	"crypto/sha256"
	"fmt"
	"time"

	"lukechampine.com/blake3"

	"github.com/macula-io/macula-go-sdk/cbor"
)

// DefaultChunkSize is 256 KiB — matches macula_manifest:default_chunk_size/0.
const DefaultChunkSize = 262_144

const (
	version       = 1
	codecRaw      = 0x55
	codecManifest = 0x56
)

// Mcid is <<Version:8, Codec:8, Hash:32/binary>> — 34 bytes.
type Mcid [34]byte

func makeMcid(codec byte, hash [32]byte) Mcid {
	var out Mcid
	out[0] = version
	out[1] = codec
	copy(out[2:], hash[:])
	return out
}

// Algorithm is a content hash algorithm.
type Algorithm int

const (
	Blake3 Algorithm = iota
	Sha256
)

func (a Algorithm) hash(data []byte) [32]byte {
	switch a {
	case Sha256:
		return sha256.Sum256(data)
	default:
		return blake3.Sum256(data)
	}
}

// Name is the wire spelling of a, used in a manifest's hash_algorithm
// field.
func (a Algorithm) Name() string {
	if a == Sha256 {
		return "sha256"
	}
	return "blake3"
}

// AlgorithmFromName matches to_algorithm/1's own fallback: anything
// unrecognized defaults to Blake3, it doesn't error.
func AlgorithmFromName(name string) Algorithm {
	if name == "sha256" {
		return Sha256
	}
	return Blake3
}

// ChunkInfo describes one chunk of a manifest.
type ChunkInfo struct {
	Index  int
	Offset int
	Size   int
	Hash   [32]byte
}

// Manifest is a chunked-content manifest.
type Manifest struct {
	Mcid          Mcid
	Version       uint32
	Name          string
	Size          uint64
	Created       uint64
	ChunkSize     int
	ChunkCount    int
	HashAlgorithm Algorithm
	RootHash      [32]byte
	Chunks        []ChunkInfo
}

// CreateOptions configures Create.
type CreateOptions struct {
	Name          string
	ChunkSize     int
	HashAlgorithm Algorithm
}

// DefaultCreateOptions matches the reference's own defaults.
func DefaultCreateOptions() CreateOptions {
	return CreateOptions{Name: "unnamed", ChunkSize: DefaultChunkSize, HashAlgorithm: Blake3}
}

// Create splits data into fixed-size chunks and builds its manifest.
// Returns the manifest and the chunk bytes in order (index 0 first) —
// a caller uploads each chunk (_content.put_block) then the manifest
// itself (_content.put_manifest), per §12.2.
//
// opts.ChunkSize must be non-zero (matches the reference: it never
// guards against zero either).
func Create(data []byte, opts CreateOptions) (Manifest, [][]byte) {
	return createWithCreated(data, opts, uint64(time.Now().Unix()))
}

func createWithCreated(data []byte, opts CreateOptions, created uint64) (Manifest, [][]byte) {
	chunks := doChunk(data, opts.ChunkSize)
	chunkInfos := makeChunkInfos(chunks, opts.HashAlgorithm)
	rootHash := rootHashFor(chunkInfos, opts.HashAlgorithm)
	chunkCount := len(chunkInfos)
	mcid := computeMcid(opts.Name, uint64(len(data)), opts.ChunkSize, chunkCount, opts.HashAlgorithm, rootHash)
	m := Manifest{
		Mcid: mcid, Version: 1, Name: opts.Name, Size: uint64(len(data)), Created: created,
		ChunkSize: opts.ChunkSize, ChunkCount: chunkCount, HashAlgorithm: opts.HashAlgorithm,
		RootHash: rootHash, Chunks: chunkInfos,
	}
	return m, chunks
}

// ChunkMcid is the MCID a chunk at index is stored/fetched under — the
// station derives this same value independently when serving the
// chunk, so both sides agree on its address without exchanging it.
func ChunkMcid(m Manifest, index int) (Mcid, bool) {
	if index < 0 || index >= len(m.Chunks) {
		return Mcid{}, false
	}
	return makeMcid(codecRaw, m.Chunks[index].Hash), true
}

// BlockMcid is the MCID a whole blob is stored/fetched under when it's
// small enough to be a single block (no manifest at all). Matches
// macula_content_transfer:put_single_block/3 exactly: ALWAYS Blake3,
// regardless of any algorithm preference -- single-block content has
// no algorithm choice, only chunked/manifest content does.
func BlockMcid(data []byte) Mcid {
	return makeMcid(codecRaw, Blake3.hash(data))
}

// McidIsChunked reports whether mcid addresses a manifest (chunked
// content) rather than a single raw block — determined from its own
// codec byte, no network round trip needed.
func McidIsChunked(mcid Mcid) bool {
	return mcid[1] == codecManifest
}

// Verify checks reassembled data against manifest: size, then a fresh
// Merkle root over data re-chunked the same way.
func Verify(m Manifest, data []byte) error {
	if uint64(len(data)) != m.Size {
		return fmt.Errorf("manifest: verify: data size %d does not match the manifest's %d", len(data), m.Size)
	}
	chunks := doChunk(data, m.ChunkSize)
	infos := makeChunkInfos(chunks, m.HashAlgorithm)
	actualRoot := rootHashFor(infos, m.HashAlgorithm)
	if actualRoot != m.RootHash {
		return fmt.Errorf("manifest: verify: re-chunked root hash does not match the manifest")
	}
	return nil
}

func doChunk(data []byte, chunkSize int) [][]byte {
	if len(data) == 0 {
		return nil
	}
	var chunks [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func makeChunkInfos(chunks [][]byte, algorithm Algorithm) []ChunkInfo {
	infos := make([]ChunkInfo, len(chunks))
	offset := 0
	for i, chunk := range chunks {
		infos[i] = ChunkInfo{Index: i, Offset: offset, Size: len(chunk), Hash: algorithm.hash(chunk)}
		offset += len(chunk)
	}
	return infos
}

func rootHashFor(infos []ChunkInfo, algorithm Algorithm) [32]byte {
	if len(infos) == 0 {
		return algorithm.hash(nil)
	}
	hashes := make([][32]byte, len(infos))
	for i, info := range infos {
		hashes[i] = info.Hash
	}
	for len(hashes) > 1 {
		hashes = combine(hashes, algorithm)
	}
	return hashes[0]
}

// combine is one Merkle-fold pass: pairs from the front, hash(L || R).
// An odd leftover at the end is paired with itself, hash(Last || Last)
// -- the rule most likely to be implemented wrong.
func combine(hashes [][32]byte, algorithm Algorithm) [][32]byte {
	out := make([][32]byte, 0, (len(hashes)+1)/2)
	for i := 0; i < len(hashes); i += 2 {
		left := hashes[i]
		right := left
		if i+1 < len(hashes) {
			right = hashes[i+1]
		}
		buf := make([]byte, 0, 64)
		buf = append(buf, left[:]...)
		buf = append(buf, right[:]...)
		out = append(out, algorithm.hash(buf))
	}
	return out
}

// computeMcid is the canonical hash input for a manifest's own MCID —
// deliberately excludes created (timestamp) and chunks (already rolled
// up into root_hash). name and hash_algorithm are wrapped as CBOR text
// here specifically, matching the reference's own special-cased
// compute_mcid/2 -- NOT the same encoding ToWire uses for name.
func computeMcid(name string, size uint64, chunkSize, chunkCount int, algorithm Algorithm, rootHash [32]byte) Mcid {
	canonical := cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("name"), Val: cbor.Text(name)},
		{Key: cbor.Text("size"), Val: cbor.Uint64(size)},
		{Key: cbor.Text("chunk_size"), Val: cbor.Uint64(uint64(chunkSize))},
		{Key: cbor.Text("chunk_count"), Val: cbor.Uint64(uint64(chunkCount))},
		{Key: cbor.Text("hash_algorithm"), Val: cbor.Text(algorithm.Name())},
		{Key: cbor.Text("root_hash"), Val: cbor.Bytes(rootHash[:])},
	})
	hash := algorithm.hash(cbor.Encode(canonical))
	return makeMcid(codecManifest, hash)
}

// ToWire encodes m as it's actually sent in a _content.put_manifest
// CALL payload -- name as bytes (its real binary() type), NOT the
// text-wrapped form computeMcid uses internally.
func ToWire(m Manifest) cbor.Value {
	chunkVals := make([]cbor.Value, len(m.Chunks))
	for i, c := range m.Chunks {
		chunkVals[i] = chunkInfoToWire(c)
	}
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("mcid"), Val: cbor.Bytes(m.Mcid[:])},
		{Key: cbor.Text("version"), Val: cbor.Uint64(uint64(m.Version))},
		{Key: cbor.Text("name"), Val: cbor.Bytes([]byte(m.Name))},
		{Key: cbor.Text("size"), Val: cbor.Uint64(m.Size)},
		{Key: cbor.Text("created"), Val: cbor.Uint64(m.Created)},
		{Key: cbor.Text("chunk_size"), Val: cbor.Uint64(uint64(m.ChunkSize))},
		{Key: cbor.Text("chunk_count"), Val: cbor.Uint64(uint64(m.ChunkCount))},
		{Key: cbor.Text("hash_algorithm"), Val: cbor.Text(m.HashAlgorithm.Name())},
		{Key: cbor.Text("root_hash"), Val: cbor.Bytes(m.RootHash[:])},
		{Key: cbor.Text("chunks"), Val: cbor.List(chunkVals)},
	})
}

func chunkInfoToWire(c ChunkInfo) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("index"), Val: cbor.Uint64(uint64(c.Index))},
		{Key: cbor.Text("offset"), Val: cbor.Uint64(uint64(c.Offset))},
		{Key: cbor.Text("size"), Val: cbor.Uint64(uint64(c.Size))},
		{Key: cbor.Text("hash"), Val: cbor.Bytes(c.Hash[:])},
	})
}

// FromWire parses a manifest as received from a _content.get_manifest
// RESULT.
func FromWire(v cbor.Value) (Manifest, error) {
	mcidB, err := getBytesExact(v, "mcid", 34)
	if err != nil {
		return Manifest{}, err
	}
	var mcid Mcid
	copy(mcid[:], mcidB)

	version, err := getUint(v, "version")
	if err != nil {
		return Manifest{}, err
	}
	name, err := getStringBytes(v, "name")
	if err != nil {
		return Manifest{}, err
	}
	size, err := getUint(v, "size")
	if err != nil {
		return Manifest{}, err
	}
	created, err := getUint(v, "created")
	if err != nil {
		return Manifest{}, err
	}
	chunkSize, err := getUint(v, "chunk_size")
	if err != nil {
		return Manifest{}, err
	}
	chunkCount, err := getUint(v, "chunk_count")
	if err != nil {
		return Manifest{}, err
	}
	algName, err := getText(v, "hash_algorithm")
	if err != nil {
		return Manifest{}, err
	}
	rootHashB, err := getBytesExact(v, "root_hash", 32)
	if err != nil {
		return Manifest{}, err
	}
	var rootHash [32]byte
	copy(rootHash[:], rootHashB)

	chunksVal, ok := v.Get("chunks")
	if !ok {
		return Manifest{}, fmt.Errorf("manifest: from_wire: missing field \"chunks\"")
	}
	chunkItems, ok := chunksVal.AsList()
	if !ok {
		return Manifest{}, fmt.Errorf("manifest: from_wire: field \"chunks\" has the wrong type")
	}
	chunks := make([]ChunkInfo, len(chunkItems))
	for i, item := range chunkItems {
		c, err := chunkInfoFromWire(item)
		if err != nil {
			return Manifest{}, err
		}
		chunks[i] = c
	}

	return Manifest{
		Mcid: mcid, Version: uint32(version), Name: name, Size: size, Created: created,
		ChunkSize: int(chunkSize), ChunkCount: int(chunkCount),
		HashAlgorithm: AlgorithmFromName(algName), RootHash: rootHash, Chunks: chunks,
	}, nil
}

func chunkInfoFromWire(v cbor.Value) (ChunkInfo, error) {
	index, err := getUint(v, "index")
	if err != nil {
		return ChunkInfo{}, err
	}
	offset, err := getUint(v, "offset")
	if err != nil {
		return ChunkInfo{}, err
	}
	size, err := getUint(v, "size")
	if err != nil {
		return ChunkInfo{}, err
	}
	hashB, err := getBytesExact(v, "hash", 32)
	if err != nil {
		return ChunkInfo{}, err
	}
	var hash [32]byte
	copy(hash[:], hashB)
	return ChunkInfo{Index: int(index), Offset: int(offset), Size: int(size), Hash: hash}, nil
}

func getUint(v cbor.Value, field string) (uint64, error) {
	fv, ok := v.Get(field)
	if !ok {
		return 0, fmt.Errorf("manifest: from_wire: missing field %q", field)
	}
	n, ok := fv.AsInt64()
	if !ok || n < 0 {
		return 0, fmt.Errorf("manifest: from_wire: field %q has the wrong type", field)
	}
	return uint64(n), nil
}

func getText(v cbor.Value, field string) (string, error) {
	fv, ok := v.Get(field)
	if !ok {
		return "", fmt.Errorf("manifest: from_wire: missing field %q", field)
	}
	t, ok := fv.AsText()
	if !ok {
		return "", fmt.Errorf("manifest: from_wire: field %q has the wrong type", field)
	}
	return t, nil
}

func getStringBytes(v cbor.Value, field string) (string, error) {
	fv, ok := v.Get(field)
	if !ok {
		return "", fmt.Errorf("manifest: from_wire: missing field %q", field)
	}
	b, ok := fv.AsBytes()
	if !ok {
		return "", fmt.Errorf("manifest: from_wire: field %q has the wrong type", field)
	}
	return string(b), nil
}

func getBytesExact(v cbor.Value, field string, n int) ([]byte, error) {
	fv, ok := v.Get(field)
	if !ok {
		return nil, fmt.Errorf("manifest: from_wire: missing field %q", field)
	}
	b, ok := fv.AsBytes()
	if !ok || len(b) != n {
		return nil, fmt.Errorf("manifest: from_wire: field %q has the wrong type", field)
	}
	return b, nil
}
