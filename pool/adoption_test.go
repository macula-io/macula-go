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
	realm, procedure := [32]byte{9}, "mcl-vault/open"
	// The pool is asked for a procedure, not for a provider: the key is filed
	// under the provider the refusal came from, which is the candidate's node.
	asked := resolvedKey{realm: realm, procedure: procedure}
	refused := resolvedKey{realm: realm, procedure: procedure, provider: node}
	p := &Pool{remember: map[resolvedKey]candidate{}, learnt: map[resolvedKey]learntKey{}}
	advertisement := candidate{Provider: Provider{Node: node, Station: station}, expiresAt: now + time.Minute.Milliseconds()}
	p.remember[asked] = advertisement
	p.learnKEMKey(refused, advertisement, carried)

	held, ok := p.remembered(asked)
	if !ok {
		t.Fatal("the asked-for key holds no candidate")
	}
	// candidates() wraps what it returns - remembered or resolved - in
	// withLearnt; this is that step.
	if got := p.withLearnt(asked.realm, asked.procedure, held); !bytes.Equal(got.kemKey, carried) {
		t.Fatalf("the remembered candidate names key %x, want the learnt %x", got.kemKey, carried)
	}

	// A candidate resolved afresh, with the same keyless advertisement, takes
	// the learnt key too.
	if got := p.withLearnt(realm, procedure, advertisement); !bytes.Equal(got.kemKey, carried) {
		t.Errorf("a freshly resolved candidate names key %x, want the learnt %x", got.kemKey, carried)
	}
	// Past the advertisement it beat, the key is not applied.
	expired := candidate{Provider: Provider{Node: node, Station: station}, expiresAt: now - 1}
	p.learnKEMKey(refused, expired, carried)
	if got := p.withLearnt(realm, procedure, advertisement); got.kemKey != nil {
		t.Errorf("a learnt key outlived its advertisement: %x", got.kemKey)
	}
	// An advertisement that names its own key is signed and fresher: it wins.
	named := carriedKey(t)
	p.learnKEMKey(refused, advertisement, carried)
	own := advertisement
	own.kemKey, own.kemKeyID = named, seal.KeyID(named)
	if got := p.withLearnt(realm, procedure, own); !bytes.Equal(got.kemKey, named) {
		t.Errorf("the advertisement's own key lost to the learnt one: %x", got.kemKey)
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
