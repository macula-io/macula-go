package cbor

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"
	"sort"
)

// MaxNestingDepth is how many list or map levels a decoded value may sit
// below the top-level value, the same cap and count as macula's decoder.
// Decoding is recursive and a frame can nest one level per byte, so the cap
// is what bounds how deep decoding goes.
const MaxNestingDepth = 128

// ErrNestingTooDeep is a value nested more than MaxNestingDepth list or map
// levels below the top-level value.
var ErrNestingTooDeep = errors.New("cbor: decode: list or map nesting exceeds 128 levels")

// Decode parses one complete CBOR value from the start of data, returning
// the value and how many bytes it consumed. Panics are not used for
// malformed input by construction — every path returns an error, since
// this parses untrusted network data (mirrors deterministic.rs's own
// panic-free-by-construction guarantee).
func Decode(data []byte) (Value, int, error) {
	v, _, n, err := decodeOne(data, 0, false)
	return v, n, err
}

// keyIdentity is what a map's duplicate keys are matched by: a digest two
// decoded values share exactly when their canonical encodings are equal. A
// scalar's is the digest of its canonical encoding. A list's is the digest of
// its head and its items' identities in order, and a map's the digest of its
// head and its entries' key and value identities, ordered by key identity.
// Only a map key, and what nests inside one, needs an identity, and each is
// worked out once, while it decodes.
type keyIdentity [sha256.Size]byte

// decodeOne decodes the value at the start of data, which sits depth list or
// map levels below the top-level value, and with withIdentity set also
// returns its key identity.
func decodeOne(data []byte, depth int, withIdentity bool) (Value, keyIdentity, int, error) {
	if depth > MaxNestingDepth {
		return Value{}, keyIdentity{}, 0, ErrNestingTooDeep
	}
	if len(data) < 1 {
		return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode: empty input")
	}
	head := data[0]
	major := head >> 5
	ai := head & 0x1F
	rest := data[1:]

	switch major {
	case majorUInt:
		n, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode uint: %w", err)
		}
		return scalar(Uint64(n), 1+used, withIdentity)

	case majorNegInt:
		n, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode negint: %w", err)
		}
		return scalar(NegInt(n), 1+used, withIdentity)

	case majorBytes:
		length, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode bytes length: %w", err)
		}
		body := rest[used:]
		if uint64(len(body)) < length {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode bytes: need %d bytes, have %d", length, len(body))
		}
		b := make([]byte, length)
		copy(b, body[:length])
		return scalar(Bytes(b), 1+used+int(length), withIdentity)

	case majorText:
		length, used, err := readAIValue(rest, ai)
		if err != nil {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode text length: %w", err)
		}
		body := rest[used:]
		if uint64(len(body)) < length {
			return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode text: need %d bytes, have %d", length, len(body))
		}
		// No UTF-8 validation on decode — matches the reference encoder's
		// own leniency (§4); a Go string is just a byte sequence.
		return scalar(Text(string(body[:length])), 1+used+int(length), withIdentity)

	case majorList:
		return decodeList(rest, ai, depth, withIdentity)

	case majorMap:
		return decodeMap(rest, ai, depth, withIdentity)

	case majorFloat:
		v, n, err := decodeMajor7(rest, ai)
		if err != nil {
			return Value{}, keyIdentity{}, 0, err
		}
		return scalar(v, n, withIdentity)

	default: // major 6 (tags): rejected outright, not supported at all.
		return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode: major type %d (tags) not supported", major)
	}
}

// scalar returns a decoded scalar and how many bytes it took, with its key
// identity when withIdentity is set.
func scalar(v Value, consumed int, withIdentity bool) (Value, keyIdentity, int, error) {
	if !withIdentity {
		return v, keyIdentity{}, consumed, nil
	}
	return v, sha256.Sum256(Encode(v)), consumed, nil
}

func decodeList(rest []byte, ai byte, depth int, withIdentity bool) (Value, keyIdentity, int, error) {
	count, used, err := readAIValue(rest, ai)
	if err != nil {
		return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode list length: %w", err)
	}
	l := listDecoder{
		rest:         rest,
		pos:          used,
		depth:        depth,
		withIdentity: withIdentity,
		items:        make([]Value, 0, preallocCap(count)),
		digest:       listDigest(count, withIdentity),
	}
	for i := uint64(0); i < count && err == nil; i++ {
		err = l.next(i)
	}
	if err != nil {
		return Value{}, keyIdentity{}, 0, err
	}
	return List(l.items), identityOf(l.digest), 1 + l.pos, nil
}

// listDecoder is a list being decoded: the bytes after its head, how far its
// items reach, and the items and identity digest so far.
type listDecoder struct {
	rest         []byte
	pos          int
	depth        int
	withIdentity bool
	items        []Value
	digest       hash.Hash
}

// listDigest starts the identity digest of a list of count items, or is nil
// when no identity is wanted.
func listDigest(count uint64, withIdentity bool) hash.Hash {
	if !withIdentity {
		return nil
	}
	digest := sha256.New()
	digest.Write(appendHead(nil, majorList, count))
	return digest
}

// next decodes item i.
func (l *listDecoder) next(i uint64) error {
	item, itemIdentity, n, err := decodeOne(l.rest[l.pos:], l.depth+1, l.withIdentity)
	if err != nil {
		return fmt.Errorf("cbor: decode list item %d: %w", i, err)
	}
	l.items = append(l.items, item)
	writeIdentity(l.digest, itemIdentity)
	l.pos += n
	return nil
}

// writeIdentity adds id to digest, when an identity is wanted.
func writeIdentity(digest hash.Hash, id keyIdentity) {
	if digest != nil {
		digest.Write(id[:])
	}
}

// entryIdentities is a decoded map entry's key and value identities.
type entryIdentities struct{ key, val keyIdentity }

func decodeMap(rest []byte, ai byte, depth int, withIdentity bool) (Value, keyIdentity, int, error) {
	count, used, err := readAIValue(rest, ai)
	if err != nil {
		return Value{}, keyIdentity{}, 0, fmt.Errorf("cbor: decode map length: %w", err)
	}
	pos := used
	// Last-write-wins on duplicate keys, per §4 — not an error.
	//
	// Duplicates are found by each key's identity through a map, not by a
	// linear scan: the scan (the previous setLastWriteWins) made this O(n^2)
	// in the key count, a pre-auth algorithmic-complexity DoS reachable
	// during frame decode before any signature check. Confirmed on the
	// equivalent pattern in the reference Rust NIF (macula-io/macula,
	// native/macula_cbor_nif): a map with 80,000 distinct keys took over a
	// minute to decode, scaling quadratically. A key's identity stands for
	// its canonical encoding, this codec's own definition of "the same key"
	// (see Encode's map-key sort), and it is worked out while the key
	// decodes: encoding each key again here, as this once did, costs a
	// nested key's size again at every level above it.
	m := mapDecoder{
		rest:         rest,
		pos:          pos,
		depth:        depth,
		withIdentity: withIdentity,
		entries:      make([]MapEntry, 0, preallocCap(count)),
		indexOfKey:   make(map[keyIdentity]int, preallocCap(count)),
		identities:   entryIdentitiesFor(count, withIdentity),
	}
	for i := uint64(0); i < count && err == nil; i++ {
		err = m.next(i)
	}
	if err != nil {
		return Value{}, keyIdentity{}, 0, err
	}
	return Map(m.entries), mapIdentity(m.identities, withIdentity), 1 + m.pos, nil
}

// mapDecoder is a map being decoded: the bytes after its head, how far its
// entries reach, the entries so far with where each key's entry is, and their
// identities when an identity is wanted.
type mapDecoder struct {
	rest         []byte
	pos          int
	depth        int
	withIdentity bool
	entries      []MapEntry
	indexOfKey   map[keyIdentity]int
	identities   []entryIdentities
}

// entryIdentitiesFor is room for count entries' identities, or nil when no
// identity is wanted.
func entryIdentitiesFor(count uint64, withIdentity bool) []entryIdentities {
	if !withIdentity {
		return nil
	}
	return make([]entryIdentities, 0, preallocCap(count))
}

// next decodes entry i's key and value and records the entry.
func (m *mapDecoder) next(i uint64) error {
	key, keyID, kn, err := decodeOne(m.rest[m.pos:], m.depth+1, true)
	if err != nil {
		return fmt.Errorf("cbor: decode map key %d: %w", i, err)
	}
	m.pos += kn
	val, valID, vn, err := decodeOne(m.rest[m.pos:], m.depth+1, m.withIdentity)
	if err != nil {
		return fmt.Errorf("cbor: decode map value %d: %w", i, err)
	}
	m.pos += vn
	m.put(key, val, entryIdentities{key: keyID, val: valID})
	return nil
}

// put records an entry, a later duplicate key replacing the value of the
// earlier entry with that key.
func (m *mapDecoder) put(key, val Value, ids entryIdentities) {
	if idx, ok := m.indexOfKey[ids.key]; ok {
		m.entries[idx].Val = val
		setValueIdentity(m.identities, idx, ids.val)
		return
	}
	m.indexOfKey[ids.key] = len(m.entries)
	m.entries = append(m.entries, MapEntry{Key: key, Val: val})
	m.identities = appendIdentities(m.identities, m.withIdentity, ids)
}

// appendIdentities is identities with ids appended, when identities are kept
// at all.
func appendIdentities(identities []entryIdentities, withIdentity bool, ids entryIdentities) []entryIdentities {
	if !withIdentity {
		return identities
	}
	return append(identities, ids)
}

// setValueIdentity records entry idx's value identity, when identities are
// kept at all.
func setValueIdentity(identities []entryIdentities, idx int, val keyIdentity) {
	if identities != nil {
		identities[idx].val = val
	}
}

// mapIdentity is the key identity of a map with these entries, once its
// duplicates have merged.
func mapIdentity(entries []entryIdentities, withIdentity bool) keyIdentity {
	if !withIdentity {
		return keyIdentity{}
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].key[:], entries[j].key[:]) < 0 })
	digest := sha256.New()
	digest.Write(appendHead(nil, majorMap, uint64(len(entries))))
	for _, e := range entries {
		digest.Write(e.key[:])
		digest.Write(e.val[:])
	}
	return identityOf(digest)
}

// identityOf is digest's sum as a key identity, or the zero identity when no
// identity was wanted.
func identityOf(digest hash.Hash) keyIdentity {
	var id keyIdentity
	if digest != nil {
		copy(id[:], digest.Sum(nil))
	}
	return id
}

// maxPreallocHint bounds a wire-supplied element count before it's used
// as a slice/map capacity hint. `count` comes straight from readAIValue
// on attacker-controlled bytes and is NOT validated against how many
// bytes actually follow -- a ~10-byte frame can claim count = 2^64-1.
// Passing that directly to make() either panics ("makeslice: cap out of
// range") or allocates gigabytes, before the per-element loop below ever
// bounds-checks against the real remaining input. This decode path has
// no recover() between it and its connection goroutine (RecvFrame ->
// frame.Decode -> cbor.Decode), so an unrecovered panic here kills the
// whole process -- a single small malformed frame as a remote DoS, found
// during review of the majorMap dedup fix above. Mirrors
// deterministic.rs's `count.min(1024)` on the equivalent
// Vec::with_capacity calls in the reference Rust NIF. The loop still
// runs the full `count` iterations; this only bounds the allocation
// hint, not correctness.
const maxPreallocHint = 1024

func preallocCap(count uint64) int {
	if count > maxPreallocHint {
		return maxPreallocHint
	}
	return int(count)
}

// readAIValue reads the value ai directly encodes (ai<=23) or the
// minimal-length extra bytes it points to (ai in {24,25,26,27}) —
// shared by majors 0/1 (where this IS the value) and 2/3/4/5 (where
// it's a length). Any other ai (28-31) is a decode error: those additional-
// info values are reserved/unused in this protocol.
func readAIValue(data []byte, ai byte) (value uint64, consumed int, err error) {
	switch {
	case ai <= maxInAI:
		return uint64(ai), 0, nil
	case ai == ai1:
		if len(data) < 1 {
			return 0, 0, fmt.Errorf("need 1 more byte")
		}
		return uint64(data[0]), 1, nil
	case ai == ai2:
		if len(data) < 2 {
			return 0, 0, fmt.Errorf("need 2 more bytes")
		}
		return uint64(binary.BigEndian.Uint16(data)), 2, nil
	case ai == ai4:
		if len(data) < 4 {
			return 0, 0, fmt.Errorf("need 4 more bytes")
		}
		return uint64(binary.BigEndian.Uint32(data)), 4, nil
	case ai == ai8:
		if len(data) < 8 {
			return 0, 0, fmt.Errorf("need 8 more bytes")
		}
		return binary.BigEndian.Uint64(data), 8, nil
	default:
		return 0, 0, fmt.Errorf("unsupported additional info %d", ai)
	}
}

// decodeMajor7 handles null and the three float widths — the only
// major-7 shapes this protocol uses. No booleans, no "undefined": any
// other AI is a decode error.
func decodeMajor7(data []byte, ai byte) (Value, int, error) {
	switch ai {
	case aiNull:
		return Null(), 1, nil
	case 25: // float16 -> f64
		if len(data) < 2 {
			return Value{}, 0, fmt.Errorf("cbor: decode float16: need 2 more bytes")
		}
		return Float(float16ToFloat64(binary.BigEndian.Uint16(data))), 3, nil
	case 26: // float32 -> f64
		if len(data) < 4 {
			return Value{}, 0, fmt.Errorf("cbor: decode float32: need 4 more bytes")
		}
		return Float(float64(math.Float32frombits(binary.BigEndian.Uint32(data)))), 5, nil
	case aiF64: // 27
		if len(data) < 8 {
			return Value{}, 0, fmt.Errorf("cbor: decode float64: need 8 more bytes")
		}
		return Float(math.Float64frombits(binary.BigEndian.Uint64(data))), 9, nil
	default:
		return Value{}, 0, fmt.Errorf("cbor: decode: major 7 additional info %d not supported (no booleans/undefined)", ai)
	}
}

// float16ToFloat64 converts an IEEE 754 binary16 value to float64.
// Decode-only path (see the package doc: this protocol never encodes
// float16, only accepts it for interop), hand-rolled to avoid a
// dependency for one conversion.
func float16ToFloat64(bits uint16) float64 {
	sign := uint64(bits>>15) & 0x1
	exp := uint64(bits>>10) & 0x1F
	frac := uint64(bits) & 0x3FF

	switch exp {
	case 0:
		if frac == 0 {
			return math.Float64frombits(sign << 63)
		}
		// Subnormal: value = frac/1024 * 2^-14.
		return math.Ldexp(float64(frac), -24) * signMul(sign)
	case 0x1F:
		if frac == 0 {
			if sign == 1 {
				return math.Inf(-1)
			}
			return math.Inf(1)
		}
		return math.NaN()
	default:
		// Normal: value = (1 + frac/1024) * 2^(exp-15).
		return math.Ldexp(1+float64(frac)/1024, int(exp)-15) * signMul(sign)
	}
}

func signMul(sign uint64) float64 {
	if sign == 1 {
		return -1
	}
	return 1
}
