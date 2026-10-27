package stationlink

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
)

// The caller's side of sealed by default (release A0,
// DESIGN_E2E_SEALED_BY_DEFAULT.md section 3): a clear call a provider refuses
// sealed_required, carrying its KEM key in the refusal's signed tbs, is sealed
// to that key once more under a new request_id.

// keyedProvider is the identity key and carried KEM key of a provider for p.
func keyedProvider(t *testing.T, p profile.Profile, name string) (*identity.NodeKey, []byte) {
	t.Helper()
	ring, err := seal.NewKeyring(p, time.Now)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return sharedIdentityKey(t, p, name), ring.Current().PublicKey().Carried()
}

// refusedClearely signs an ERROR answering r, carrying the KEM key under
// seal.kem_key when carried is not nil.
func refusedClearely(t *testing.T, r frame.VerifiedRequest, code string, carried []byte, signer *identity.NodeKey) (cbor.Value, bool) {
	t.Helper()
	var exts []frame.Ext
	if carried != nil {
		exts = []frame.Ext{{Name: frame.ExtSealKEMKey, Value: cbor.Bytes(carried)}}
	}
	reply, err := frame.SignProviderErrorWithExt(r, code, nil, exts, nil, signer)
	if err != nil {
		t.Errorf("sign %s: %v", code, err)
		return cbor.Value{}, false
	}
	return reply, true
}

// A clear call refused sealed_required with a carried key is sealed to that
// key and sent again, and the pool is handed the key.
func TestAClearCallResealsToTheKeyTheRefusalCarries(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			link, s := linkWithStation(t, p)
			provider, carried := keyedProvider(t, p, "a keyed provider")
			var mu sync.Mutex
			var sent []frame.VerifiedRequest
			s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
				mu.Lock()
				sent = append(sent, r)
				n := len(sent)
				mu.Unlock()
				if n == 1 {
					return refusedClearely(t, r, codeSealedRequired, carried, provider)
				}
				// A clear refusal from the closed set, which a sealed call may
				// take: the call ends here, whatever the answer is.
				return refusedClearely(t, r, "unavailable", nil, provider)
			})
			var adopted []byte
			_, err := callWithin(t, link, Call{Procedure: "mcl-vault/open", Target: provider.KeyID(), Payload: cbor.Text("a secret"),
				Clear: true, Timeout: 5 * time.Second, Adopted: func(key []byte) { adopted = key }})
			var refused *ProviderError
			if !errors.As(err, &refused) || refused.Code != "unavailable" {
				t.Fatalf("Call: %v, want the second call's own refusal", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if len(sent) != 2 {
				t.Fatalf("the provider answered %d calls, want 2", len(sent))
			}
			first, second := sent[0], sent[1]
			if first.Sealed != nil {
				t.Error("the first call went out sealed, want it clear")
			}
			if first.RequestID == second.RequestID {
				t.Error("the reseal kept the first request_id, want a new one")
			}
			if second.Sealed == nil || second.Sealed.KeyID != seal.KeyID(carried) {
				t.Errorf("the second call's seal: %+v, want the carried key %x", second.Sealed, seal.KeyID(carried))
			}
			if string(adopted) != string(carried) {
				t.Errorf("the pool was handed %x, want the carried key %x", adopted, carried)
			}
		})
	}
}

// A refusal naming a key of another profile's length is not resealed: it
// surfaces as the provider's own refusal, and one call is all that goes out.
func TestARefusalWithAKeyOfTheWrongLengthIsNotResealed(t *testing.T) {
	p := profile.PQPure
	link, s := linkWithStation(t, p)
	provider, carried := keyedProvider(t, p, "a short key")
	var mu sync.Mutex
	answers := 0
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		mu.Lock()
		answers++
		mu.Unlock()
		return refusedClearely(t, r, codeSealedRequired, carried[:32], provider)
	})
	_, err := callWithin(t, link, Call{Procedure: "mcl-vault/open", Target: provider.KeyID(), Payload: cbor.Text("a secret"),
		Clear: true, Timeout: 5 * time.Second})
	var refused *ProviderError
	if !errors.As(err, &refused) || refused.Code != codeSealedRequired {
		t.Fatalf("Call: %v, want the provider's sealed_required", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if answers != 1 {
		t.Errorf("the provider answered %d calls, want 1: a key of the wrong length is no key", answers)
	}
}

// A sealed call is never resealed by the link: A1's reseal is the pool's, and
// only on sealed_refused.
func TestASealedCallIsNotResealedByTheLink(t *testing.T) {
	p := profile.PQPure
	link, s := linkWithStation(t, p)
	provider, carried := keyedProvider(t, p, "a sealed caller")
	var mu sync.Mutex
	answers := 0
	s.answerCalls(func(r frame.VerifiedRequest) (cbor.Value, bool) {
		mu.Lock()
		answers++
		mu.Unlock()
		return refusedClearely(t, r, "unavailable", carried, provider)
	})
	_, err := callWithin(t, link, Call{Procedure: "mcl-vault/open", Target: provider.KeyID(), Payload: cbor.Text("a secret"),
		SealTo: carried, Timeout: 5 * time.Second})
	var refused *ProviderError
	if !errors.As(err, &refused) || refused.Code != "unavailable" {
		t.Fatalf("Call: %v, want the provider's refusal", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if answers != 1 {
		t.Errorf("the provider answered %d calls, want 1", answers)
	}
}
