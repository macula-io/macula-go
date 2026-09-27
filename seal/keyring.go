package seal

import (
	"sync"
	"time"

	"github.com/macula-io/macula-go/profile"
)

// A provider's KEM keys (macula 13's E2E design, amendment A1): the key its
// advertisements name, rotated every KeyLifetime, and each replaced key kept
// for RetiredKeyKept, long enough that a request sealed to it just before the
// rotation can still be admitted (the last advertisement's 5 minutes, the D22
// clock tolerance's 5, the longest deadline's 10, admission's 5 past it, and 5
// of margin), then forgotten. Keys live in memory only, never on disk: a
// restart loses them all, and a caller sealing to an old one is refused
// sealed_refused, naming the new one. One node identity, one keyring.
const (
	KeyLifetime    = 24 * time.Hour
	RetiredKeyKept = 30 * time.Minute
)

// Keyring holds one node identity's KEM keys. It is safe for concurrent use.
type Keyring struct {
	profile profile.Profile
	now     func() time.Time

	mu        sync.Mutex
	current   *PrivateKey
	currentID [KeyIDSize]byte
	since     time.Time
	retired   []retiredKey
}

type retiredKey struct {
	key   *PrivateKey
	id    [KeyIDSize]byte
	until time.Time
}

// NewKeyring is a keyring of profile p with a fresh current key, reading the
// time from now.
func NewKeyring(p profile.Profile, now func() time.Time) (*Keyring, error) {
	key, err := GenerateKey(p)
	if err != nil {
		return nil, err
	}
	return &Keyring{profile: p, now: now, current: key, currentID: KeyID(key.PublicKey().Carried()), since: now()}, nil
}

// Profile is the profile of every key the keyring holds.
func (r *Keyring) Profile() profile.Profile { return r.profile }

// Current is the key an advertisement names now, rotated first when it has
// lived KeyLifetime. Every advertisement reads it when it is signed, so a
// renewal names a rotated key.
func (r *Keyring) Current() *PrivateKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotate(r.now())
	return r.current
}

// Find is the key of id: the current key, or a replaced one still kept.
func (r *Keyring) Find(id [KeyIDSize]byte) (*PrivateKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.rotate(now)
	if r.currentID == id {
		return r.current, true
	}
	for _, old := range r.retired {
		if old.id == id && now.Before(old.until) {
			return old.key, true
		}
	}
	return nil, false
}

// CurrentID is the id of the current key, which a sealed_refused names.
func (r *Keyring) CurrentID() [KeyIDSize]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rotate(r.now())
	return r.currentID
}

// rotate replaces the current key once it has lived KeyLifetime, keeping it
// for RetiredKeyKept, and forgets the replaced keys past theirs. r.mu is held.
func (r *Keyring) rotate(now time.Time) {
	kept := r.retired[:0]
	for _, old := range r.retired {
		if now.Before(old.until) {
			kept = append(kept, old)
		}
	}
	r.retired = kept
	if now.Sub(r.since) < KeyLifetime {
		return
	}
	next, err := GenerateKey(r.profile)
	if err != nil {
		// The profile was checked when the keyring was made, and crypto/rand
		// does not fail: keep the current key rather than hold none.
		return
	}
	r.retired = append(r.retired, retiredKey{key: r.current, id: r.currentID, until: now.Add(RetiredKeyKept)})
	r.current, r.currentID, r.since = next, KeyID(next.PublicKey().Carried()), now
}
