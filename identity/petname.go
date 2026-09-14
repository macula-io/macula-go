// Petnames: a deterministic, human-readable label for a mesh node id —
// Docker's adjective_color_animal convention with a four-digit suffix
// (e.g. "happy_green_rabbit_4831"). A pure function of the node id
// itself, not random per process: the same identity gets the same
// petname across restarts, across every tool that shows it, and on
// every other agent's roster too.
//
// The suffix exists because the mesh is expected to host THOUSANDS of
// agents: the word trio alone (64,000 combinations) collides visibly
// under the birthday problem at a few hundred identities; the trio
// plus a 4-digit hash group (640,000,000 combinations) stays
// effectively collision-free at fleet scale while remaining scannable.
//
// The word lists and derivation are shared verbatim with macula-mcp's
// own petname implementation (and macula-rust's port): same sha256 of
// the lowercased hex id, same 16-bit reads modulo the list lengths,
// plus the suffix group. This package is the REFERENCE implementation
// the FFI-wrapped SDKs (TypeScript, PHP) inherit.

package identity

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"
)

var adjectivesA = [...]string{
	"bold", "bouncy", "brave", "breezy", "calm", "cheerful", "clever", "curious",
	"daring", "eager", "elegant", "fierce", "gentle", "graceful", "humble", "jolly",
	"jovial", "keen", "kind", "lively", "lucky", "mellow", "merry", "nimble",
	"noble", "plucky", "proud", "quiet", "quirky", "radiant", "silly", "sleepy",
	"spry", "sturdy", "tranquil", "upbeat", "vivid", "wise", "witty", "zealous",
}

var adjectivesB = [...]string{
	"amber", "azure", "bronze", "coral", "crimson", "cyan", "emerald", "golden",
	"green", "indigo", "ivory", "jade", "lavender", "lilac", "magenta", "maroon",
	"mauve", "navy", "olive", "orange", "peach", "pink", "plum", "purple",
	"red", "rust", "ruby", "sage", "salmon", "scarlet", "sienna", "silver",
	"slate", "tan", "teal", "turquoise", "violet", "yellow", "blue", "copper",
}

var nouns = [...]string{
	"antelope", "badger", "beetle", "bison", "cricket", "dolphin", "eagle", "elk",
	"falcon", "ferret", "flamingo", "fox", "gazelle", "gecko", "hare", "heron",
	"ibex", "iguana", "lynx", "marten", "mongoose", "moose", "narwhal", "orca",
	"otter", "owl", "panther", "pelican", "penguin", "rabbit", "raven", "salamander",
	"seal", "sparrow", "tiger", "toucan", "walrus", "weasel", "wolf", "wombat",
}

// Petname returns the stable "adjective_color_animal_0000" label for a
// node id: same input, same output, on every tool and every machine.
func Petname(nodeID string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(nodeID)))
	a := adjectivesA[binary.BigEndian.Uint16(digest[0:2])%uint16(len(adjectivesA))]
	b := adjectivesB[binary.BigEndian.Uint16(digest[2:4])%uint16(len(adjectivesB))]
	n := nouns[binary.BigEndian.Uint16(digest[4:6])%uint16(len(nouns))]
	suffix := binary.BigEndian.Uint16(digest[6:8]) % 10_000
	return fmt.Sprintf("%s_%s_%s_%04d", a, b, n, suffix)
}
