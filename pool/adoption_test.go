package pool

import (
	"bytes"
	"testing"
	"time"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// The key a provider's signed refusal names beats the keyless advertisement it
// answered, for that advertisement's remaining lifetime
// (DESIGN_E2E_SEALED_BY_DEFAULT.md section 3): the next call seals at once,
// rather than going clear and being refused again.
func TestALearntKeyBeatsAKeylessAdvertisement(t *testing.T) {
	carried := carriedKey(t)
	now := time.Now().UnixMilli()
	node, station := [32]byte{1}, [32]byte{2}
	key := resolvedKey{procedure: "mcl-vault/open", provider: node}
	p := &Pool{remember: map[resolvedKey]candidate{}, learnt: map[resolvedKey]learntKey{}}
	advertisement := candidate{Provider: Provider{Node: node, Station: station}, expiresAt: now + time.Minute.Milliseconds()}
	p.remember[key] = advertisement
	p.learnKEMKey(key, advertisement, carried)
	held, ok := p.remembered(key)
	if !ok || !bytes.Equal(held.kemKey, carried) {
		t.Fatalf("the remembered candidate names key %x, want the learnt %x", held.kemKey, carried)
	}
	// Past the advertisement the pool resolves afresh.
	p.learnKEMKey(key, candidate{Provider: Provider{Node: node, Station: station}, expiresAt: now - 1}, carried)
	if held, _ := p.remembered(key); held.kemKey != nil {
		t.Errorf("a learnt key outlived its advertisement: %x", held.kemKey)
	}
	// An advertisement that names its own key is signed and fresher: it wins.
	named := carriedKey(t)
	p.learnKEMKey(key, advertisement, carried)
	p.remember[key] = candidate{Provider: Provider{Node: node, Station: station},
		expiresAt: advertisement.expiresAt, kemKey: named, kemKeyID: seal.KeyID(named)}
	if held, _ := p.remembered(key); !bytes.Equal(held.kemKey, named) {
		t.Errorf("the advertisement's own key lost to the learnt one: %x", held.kemKey)
	}
}

// carriedKey is a KEM key of the test profile, as an advertisement carries it.
func carriedKey(t *testing.T) []byte {
	t.Helper()
	k, err := seal.GenerateKey(profile.PQPure)
	if err != nil {
		t.Fatalf("seal key: %v", err)
	}
	return k.PublicKey().Carried()
}
