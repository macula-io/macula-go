// Package manifest implements fixed-size chunking, Merkle-root
// computation, and manifest construction for content larger than one
// storage block, as macula 12's macula_manifest does, byte for byte: SHA-384
// hashes, a 50-byte MCID <<2, Codec, SHA-384>> (tag 2 names SHA-384, D24), a
// 256 KiB default chunk size, and a Merkle fold that pairs an odd last hash
// with itself. testdata/erlang_manifests.json holds manifests macula built,
// checked in every go test.
//
// Two different wire representations of name, both handled separately,
// not confused with each other: computeMcid's canonical hash input
// wraps name as CBOR text (a deliberate, narrow special case, just for
// that hash computation), while ToWire — the actual manifest map sent
// in a _content.put_manifest CALL payload — encodes name as a raw byte
// string, matching its binary() type.
package manifest

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"

	"github.com/macula-io/macula-go/cbor"
)

// DefaultChunkSize is 256 KiB — matches macula_manifest:default_chunk_size/0.
const DefaultChunkSize = 262_144

const (
	version       = 1
	tagSHA384     = 2
	codecRaw      = 0x55
	codecManifest = 0x56
)

// HashSize is a SHA-384 digest's length.
const HashSize = 48

// Mcid is <<Tag:8, Codec:8, Hash:48/binary>>, 50 bytes: tag 2 is SHA-384,
// codec 0x55 a raw block and 0x56 a manifest.
type Mcid [50]byte

// Hash is a SHA-384 digest.
type Hash = [HashSize]byte

func makeMcid(codec byte, hash Hash) Mcid {
	var out Mcid
	out[0] = tagSHA384
	out[1] = codec
	copy(out[2:], hash[:])
	return out
}

// Algorithm is a content hash algorithm. SHA384 is the only one: macula 12
// hashes content with SHA-384 and refuses a manifest naming another.
type Algorithm int

// SHA384 is SHA-384, the hash algorithm of every manifest.
const SHA384 Algorithm = 0

func (a Algorithm) hash(data []byte) Hash {
	return sha512.Sum384(data)
}

// Name is the wire spelling of a manifest's hash_algorithm field: "sha384".
func (a Algorithm) Name() string {
	return "sha384"
}

// ChunkInfo describes one chunk of a manifest.
type ChunkInfo struct {
	Index  int
	Offset int
	Size   int
	Hash   Hash
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
	RootHash      Hash
	Chunks        []ChunkInfo
}

// CreateOptions configures Create. A manifest's hash algorithm is always
// SHA-384, so there is no option for it.
type CreateOptions struct {
	Name      string
	ChunkSize int
}

// DefaultCreateOptions matches the reference's own defaults.
func DefaultCreateOptions() CreateOptions {
	return CreateOptions{Name: "unnamed", ChunkSize: DefaultChunkSize}
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
	chunkInfos := makeChunkInfos(chunks, SHA384)
	rootHash := rootHashFor(chunkInfos, SHA384)
	chunkCount := len(chunkInfos)
	mcid := computeMcid(opts.Name, uint64(len(data)), opts.ChunkSize, chunkCount, SHA384, rootHash)
	m := Manifest{
		Mcid: mcid, Version: 1, Name: opts.Name, Size: uint64(len(data)), Created: created,
		ChunkSize: opts.ChunkSize, ChunkCount: chunkCount, HashAlgorithm: SHA384,
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
// macula_content_transfer:put_single_block/3 exactly: <<2, 0x55,
// SHA-384(data)>>.
func BlockMcid(data []byte) Mcid {
	return makeMcid(codecRaw, SHA384.hash(data))
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
	if m.ChunkSize <= 0 {
		return fmt.Errorf("manifest: verify: chunk size %d is not positive", m.ChunkSize)
	}
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

// ErrManifestMcidMismatch is a manifest that doesn't describe the MCID it
// was fetched for.
var ErrManifestMcidMismatch = errors.New("manifest: the manifest does not describe the requested mcid")

// ErrManifestNotWhole is a manifest whose chunks don't describe its content
// whole.
var ErrManifestNotWhole = errors.New("manifest: the manifest's chunks do not describe its content whole")

// McidFor is the MCID m's canonical fields describe: its name, size,
// chunk_size, chunk_count, hash_algorithm and root_hash.
func McidFor(m Manifest) Mcid {
	return computeMcid(m.Name, m.Size, m.ChunkSize, m.ChunkCount, m.HashAlgorithm, m.RootHash)
}

// VerifyMcid checks that m describes mcid, the way macula_manifest's
// verify_mcid/2 does: m's name must be valid UTF-8, its hash algorithm
// sha384, and the MCID recomputed from its canonical fields (McidFor) must
// equal mcid. m's own Mcid field is not consulted.
func VerifyMcid(m Manifest, mcid Mcid) error {
	if !utf8.ValidString(m.Name) || m.HashAlgorithm != SHA384 || McidFor(m) != mcid {
		return ErrManifestMcidMismatch
	}
	return nil
}

// CheckWhole checks that m's chunks describe its content whole, cut the way
// Create cuts content: ChunkSize is positive, and there are ceil(Size /
// ChunkSize) chunks, which is ChunkCount; chunk i has index i, starts at
// i x ChunkSize and is ChunkSize bytes long, except the last, which holds
// what is left of Size, between 1 and ChunkSize bytes.
func CheckWhole(m Manifest) error {
	if m.ChunkSize <= 0 || m.ChunkCount != len(m.Chunks) || uint64(m.ChunkCount) != chunksFor(m.Size, m.ChunkSize) {
		return fmt.Errorf("%w: chunk size %d, size %d, %d chunks counted, %d listed", ErrManifestNotWhole, m.ChunkSize, m.Size, m.ChunkCount, len(m.Chunks))
	}
	i := 0
	for i < len(m.Chunks) && cutAt(m.Chunks[i], i, m) {
		i++
	}
	if i < len(m.Chunks) {
		return fmt.Errorf("%w: chunk %d", ErrManifestNotWhole, i)
	}
	return nil
}

// ErrManifestChunkHashes is a manifest whose chunk hashes don't combine to its
// root hash.
var ErrManifestChunkHashes = errors.New("manifest: the manifest's chunk hashes do not make its root hash")

// CheckChunkHashes checks that m's chunk hashes combine to its root hash, the
// way Create builds the root hash from them. The root hash is part of m's
// MCID and the chunk hashes are not, so after VerifyMcid this is what ties
// each chunk, fetched by its hash, to the MCID asked for.
func CheckChunkHashes(m Manifest) error {
	if rootHashFor(m.Chunks, m.HashAlgorithm) != m.RootHash {
		return ErrManifestChunkHashes
	}
	return nil
}

// chunksFor is how many chunks of chunkSize bytes size bytes make:
// ceil(size / chunkSize), and 0 for no bytes.
func chunksFor(size uint64, chunkSize int) uint64 {
	n := size / uint64(chunkSize)
	if size%uint64(chunkSize) != 0 {
		n++
	}
	return n
}

// cutAt reports whether c is chunk i of m as Create cuts it. It relies on
// m already having ceil(Size / ChunkSize) chunks, so chunk i starts inside
// Size.
func cutAt(c ChunkInfo, i int, m Manifest) bool {
	offset := uint64(i) * uint64(m.ChunkSize)
	size := min(uint64(m.ChunkSize), m.Size-offset)
	return c.Index == i && c.Offset >= 0 && uint64(c.Offset) == offset && c.Size > 0 && uint64(c.Size) == size
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

func rootHashFor(infos []ChunkInfo, algorithm Algorithm) Hash {
	if len(infos) == 0 {
		return algorithm.hash(nil)
	}
	hashes := make([]Hash, len(infos))
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
func combine(hashes []Hash, algorithm Algorithm) []Hash {
	out := make([]Hash, 0, (len(hashes)+1)/2)
	for i := 0; i < len(hashes); i += 2 {
		left := hashes[i]
		right := left
		if i+1 < len(hashes) {
			right = hashes[i+1]
		}
		buf := make([]byte, 0, 2*HashSize)
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
func computeMcid(name string, size uint64, chunkSize, chunkCount int, algorithm Algorithm, rootHash Hash) Mcid {
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
// RESULT, as macula_manifest's from_wire/1 does. A manifest that does not name
// sha384 as its hash algorithm, whose chunks don't describe its content whole
// (see CheckWhole), or holding a number too large for the field it fills, is
// refused. Nothing is allocated from the size or count it claims: only the
// chunks it lists, which the frame bounds, are read.
func FromWire(v cbor.Value) (Manifest, error) {
	mcidB, err := getBytesExact(v, "mcid", len(Mcid{}))
	if err != nil {
		return Manifest{}, err
	}
	var mcid Mcid
	copy(mcid[:], mcidB)

	version, err := getBounded(v, "version", math.MaxUint32)
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
	chunkSize, err := getBounded(v, "chunk_size", math.MaxInt)
	if err != nil {
		return Manifest{}, err
	}
	chunkCount, err := getBounded(v, "chunk_count", math.MaxInt)
	if err != nil {
		return Manifest{}, err
	}
	algorithm, err := wireAlgorithm(v)
	if err != nil {
		return Manifest{}, err
	}
	rootHashB, err := getBytesExact(v, "root_hash", HashSize)
	if err != nil {
		return Manifest{}, err
	}
	var rootHash Hash
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

	m := Manifest{
		Mcid: mcid, Version: uint32(version), Name: name, Size: size, Created: created,
		ChunkSize: int(chunkSize), ChunkCount: int(chunkCount),
		HashAlgorithm: algorithm, RootHash: rootHash, Chunks: chunks,
	}
	if err := CheckWhole(m); err != nil {
		return Manifest{}, fmt.Errorf("manifest: from_wire: %w", err)
	}
	return m, nil
}

// wireAlgorithm reads a manifest's hash_algorithm the way macula_manifest's
// from_wire/1 does: sha384, as text or bytes, is the one algorithm a manifest
// can name, and a manifest that names none or another, sha256 or blake3
// among them, is refused.
func wireAlgorithm(v cbor.Value) (Algorithm, error) {
	field, ok := v.Get("hash_algorithm")
	if !ok {
		return SHA384, fmt.Errorf("manifest: from_wire: no hash_algorithm")
	}
	name, isText := field.AsText()
	if !isText {
		b, _ := field.AsBytes()
		name = string(b)
	}
	if name != SHA384.Name() {
		return SHA384, fmt.Errorf("manifest: from_wire: hash_algorithm %q is not sha384", name)
	}
	return SHA384, nil
}

func chunkInfoFromWire(v cbor.Value) (ChunkInfo, error) {
	index, err := getBounded(v, "index", math.MaxInt)
	if err != nil {
		return ChunkInfo{}, err
	}
	offset, err := getBounded(v, "offset", math.MaxInt)
	if err != nil {
		return ChunkInfo{}, err
	}
	size, err := getBounded(v, "size", math.MaxInt)
	if err != nil {
		return ChunkInfo{}, err
	}
	hashB, err := getBytesExact(v, "hash", HashSize)
	if err != nil {
		return ChunkInfo{}, err
	}
	var hash Hash
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

// getBounded reads field as an unsigned integer no larger than limit, so it
// keeps its value when it becomes the narrower type its field holds, whatever
// the size of an int.
func getBounded(v cbor.Value, field string, limit uint64) (uint64, error) {
	n, err := getUint(v, field)
	if err != nil {
		return 0, err
	}
	if n > limit {
		return 0, fmt.Errorf("manifest: from_wire: field %q is larger than %d", field, limit)
	}
	return n, nil
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
