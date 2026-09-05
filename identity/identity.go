// Package identity implements Macula's peer identity: an Ed25519 keypair,
// S/Kademlia puzzle-hardened at generation time (see
// plans/PLAN_WIRE_PROTOCOL.md §5). Every station checks
// PuzzleEvidence against DefaultPuzzleDifficulty on every CONNECT, for
// every kind of dialer, not just station-to-station peering — grinding
// this once at identity creation (never per connection) is not optional
// for a client that wants its subscriptions and calls to actually work.
// See KeyPair.HasValidPuzzle's doc for the real incident this guards
// against: an unhardened identity's QUIC/TLS handshake completes and
// subscribe calls return {ok, _}, while the station silently drops the
// application-layer HELLO — a link that looks fully healthy and delivers
// nothing, for as long as nobody thinks to check the puzzle.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
)

// DefaultPuzzleDifficulty is the leading-zero-bit count a fresh identity's
// PuzzleEvidence must satisfy. Matches macula_identity's own default
// (?DEFAULT_PUZZLE_DIFFICULTY = 8); grinding at this difficulty is
// sub-millisecond.
const DefaultPuzzleDifficulty = 8

// KeyPair is a Macula peer identity: an Ed25519 keypair whose public key
// (NodeID) satisfies the puzzle difficulty it was minted for.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// NodeID is the 32-byte Ed25519 public key this identity is known by on
// the wire (CONNECT/HELLO's node_id field).
func (k KeyPair) NodeID() []byte {
	return []byte(k.Public)
}

// Valid reports whether k has real Ed25519 key material (the exact
// sizes Generate/Load/FromSeed always produce), as opposed to an
// unconstructed zero-value KeyPair{}. Signing with a zero-value KeyPair
// panics inside ed25519.Sign; a caller accepting a KeyPair from
// somewhere else (a config struct, a pool's Opts) should check this
// before using it, so a caller's mistake surfaces as a clear error
// instead of a panic on whatever goroutine happens to sign first —
// found live 2026-09-05 doing exactly that inside a connection pool's
// own background dial goroutine, well after the call that accepted the
// bad identity had already returned success.
func (k KeyPair) Valid() bool {
	return len(k.Public) == ed25519.PublicKeySize && len(k.Private) == ed25519.PrivateKeySize
}

// PuzzleEvidence is SHA-256(NodeID) — a plain, deterministic hash of the
// node's own public key, carried in every CONNECT frame's
// puzzle_evidence field. No nonce, no per-connection computation: this
// is a property of the identity, computed once.
func (k KeyPair) PuzzleEvidence() [32]byte {
	return sha256.Sum256(k.NodeID())
}

// HasValidPuzzle reports whether this identity's PuzzleEvidence has at
// least difficulty leading zero bits — the same check
// macula_identity:puzzle_valid/2 runs on every station. An identity
// minted by GenerateWithPuzzle always satisfies this at the difficulty
// it was ground for; this exists mainly so a caller can assert it rather
// than trust the grind blindly.
func (k KeyPair) HasValidPuzzle(difficulty uint32) bool {
	return leadingZeroBits(k.PuzzleEvidence()) >= difficulty
}

func leadingZeroBits(hash [32]byte) uint32 {
	var n uint32
	for _, b := range hash {
		if b == 0 {
			n += 8
			continue
		}
		for mask := byte(0x80); mask != 0; mask >>= 1 {
			if b&mask != 0 {
				return n
			}
			n++
		}
	}
	return n
}

// Generate mints a fresh identity at DefaultPuzzleDifficulty. This is
// the entry point every caller should reach for — see the package doc
// for why an unhardened identity is a silent, hard-to-diagnose failure
// mode, not a shortcut.
func Generate() (KeyPair, error) {
	return GenerateWithPuzzle(DefaultPuzzleDifficulty)
}

// GenerateWithPuzzle mints a fresh Ed25519 keypair, discarding candidates
// until one's PuzzleEvidence has at least difficulty leading zero bits
// (S/Kademlia Sybil defense — this makes minting an identity expensive,
// not any single connection). Call once, at first run, and persist the
// result (Save) — never re-grind per connection.
func GenerateWithPuzzle(difficulty uint32) (KeyPair, error) {
	for {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return KeyPair{}, fmt.Errorf("identity: generate: %w", err)
		}
		kp := KeyPair{Public: pub, Private: priv}
		if kp.HasValidPuzzle(difficulty) {
			return kp, nil
		}
	}
}

// Save persists the 32-byte Ed25519 seed to path with 0600 permissions —
// the same "secure local file, restrictive mode" analog
// macula_identity:save/2 uses (mirrored here by a plain file write; a
// mobile port should use Keychain/Keystore instead, see
// plans/PLAN_WIRE_PROTOCOL.md §5's "Lifecycle" note).
func (k KeyPair) Save(path string) error {
	seed := k.Private.Seed()
	return os.WriteFile(path, seed, 0o600)
}

// Load reconstructs a KeyPair from a 32-byte seed file written by Save.
// Deterministic: the same seed always yields the same keypair, so this
// never re-grinds — the puzzle was already satisfied when the seed was
// first generated, and a valid seed's derived key still satisfies it.
func Load(path string) (KeyPair, error) {
	seed, err := os.ReadFile(path)
	if err != nil {
		return KeyPair{}, fmt.Errorf("identity: load: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return KeyPair{}, fmt.Errorf("identity: load: seed file is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return KeyPair{Public: pub, Private: priv}, nil
}

// FromSeed reconstructs a KeyPair from a 32-byte Ed25519 seed directly
// (no file I/O) — for tests and for callers with their own key storage.
// Deterministic, and does not check the puzzle: a caller passing a seed
// that doesn't satisfy any particular difficulty gets exactly that
// identity back, unchanged.
func FromSeed(seed []byte) (KeyPair, error) {
	if len(seed) != ed25519.SeedSize {
		return KeyPair{}, fmt.Errorf("identity: FromSeed: seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return KeyPair{Public: pub, Private: priv}, nil
}

// Sign signs data with this identity's private key.
func (k KeyPair) Sign(data []byte) []byte {
	return ed25519.Sign(k.Private, data)
}

// Verify reports whether sig is a valid Ed25519 signature over data by
// the identity whose public key is nodeID.
func Verify(nodeID, data, sig []byte) bool {
	if len(nodeID) != ed25519.PublicKeySize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(nodeID), data, sig)
}
