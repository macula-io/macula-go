package ucan

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The vectors are macula's test/vectors/ucan_v1.json (UCAN_V1.md beside it)
// at 0e2724cc97a5689542b8da7b06d392cf0d34b205, copied by
// scripts/interop/copy_ucan_vectors.sh: tokens macula_ucan minted,
// each with its policy, context and the verdict macula_ucan:authorize/3
// reaches. Every verdict here must be macula's.

type vectorKey struct {
	NodeID string `json:"node_id"`
	KeyID  string `json:"key_id"`
	DIDKey string `json:"did_key"`
}

type vectorPolicy struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	KeyID  string `json:"key_id"`
	Can    string `json:"can"`
}

type vectorContext struct {
	Caller    string `json:"caller"`
	Now       int64  `json:"now"`
	Realm     string `json:"realm"`
	Procedure string `json:"procedure"`
}

type vectorCase struct {
	Name    string        `json:"name"`
	Token   string        `json:"token"`
	Proofs  []string      `json:"proofs"`
	Policy  vectorPolicy  `json:"policy"`
	Context vectorContext `json:"context"`
	Verdict string        `json:"verdict"`
}

type vectorProfile struct {
	Keys     map[string]vectorKey `json:"keys"`
	Cases    []vectorCase         `json:"cases"`
	ProofIDs []struct {
		Token   string `json:"token"`
		ProofID string `json:"proof_id"`
	} `json:"proof_ids"`
}

type vectorFile struct {
	Profiles map[string]vectorProfile `json:"profiles"`
	Covers   []struct {
		Parent string `json:"parent"`
		Child  string `json:"child"`
		Covers bool   `json:"covers"`
	} `json:"covers"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ucan_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Profiles) != 2 || len(v.Covers) == 0 {
		t.Fatalf("vectors hold %d profiles and %d covers entries", len(v.Profiles), len(v.Covers))
	}
	return v
}

func id32(t *testing.T, text string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(text)
	if err != nil || len(b) != 32 {
		t.Fatalf("%q is not a 32-byte id", text)
	}
	return [32]byte(b)
}

func (p vectorPolicy) policy(t *testing.T) Policy {
	switch p.Kind {
	case "ucan_required":
		return UCANRequired{Issuer: id32(t, p.Issuer)}
	case "realm_member_required":
		return RealmMemberRequired{KeyID: id32(t, p.KeyID), Can: p.Can}
	}
	t.Fatalf("a policy of kind %q", p.Kind)
	return nil
}

func (c vectorCase) context(t *testing.T, prof profile.Profile) Context {
	ctx := Context{Caller: id32(t, c.Context.Caller), Profile: prof, Now: c.Context.Now, Proofs: map[string][]byte{}}
	for _, proof := range c.Proofs {
		ctx.Proofs[ProofID([]byte(proof))] = []byte(proof)
	}
	if c.Context.Realm != "" {
		ctx.Request = &Request{Realm: id32(t, c.Context.Realm), Procedure: c.Context.Procedure}
	}
	return ctx
}

// verdict is an authorization's outcome by macula's name for it.
func verdict(err error) string {
	if err == nil {
		return "ok"
	}
	return RefusalName(err)
}

func TestVectorsAuthorizeAsMacula(t *testing.T) {
	v := loadVectors(t)
	for name, p := range v.Profiles {
		prof, err := profile.Parse(name)
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Cases) == 0 {
			t.Fatalf("%s holds no cases", name)
		}
		for _, c := range p.Cases {
			t.Run(name+"/"+c.Name, func(t *testing.T) {
				_, err := Authorize([]byte(c.Token), c.Policy.policy(t), c.context(t, prof))
				if got := verdict(err); got != c.Verdict {
					t.Fatalf("verdict %s (%v), macula's is %s", got, err, c.Verdict)
				}
			})
		}
	}
}

func TestVectorsProofIDs(t *testing.T) {
	v := loadVectors(t)
	for name, p := range v.Profiles {
		if len(p.ProofIDs) == 0 {
			t.Fatalf("%s holds no proof ids", name)
		}
		for _, e := range p.ProofIDs {
			if got := ProofID([]byte(e.Token)); got != e.ProofID {
				t.Errorf("%s: proof id %s, want %s", name, got, e.ProofID)
			}
		}
	}
}

// Each key's did:key decodes to a key whose key id, and node_id where it has
// one, are the vector's, and encodes back to the same did:key.
func TestVectorsKeys(t *testing.T) {
	v := loadVectors(t)
	for name, p := range v.Profiles {
		prof, _ := profile.Parse(name)
		for keyName, k := range p.Keys {
			carried, err := CarriedKey(k.DIDKey, prof)
			if err != nil {
				t.Fatalf("%s %s: %v", name, keyName, err)
			}
			if got := DIDKey(carried, prof); got != k.DIDKey {
				t.Errorf("%s %s: did:key does not round trip", name, keyName)
			}
			if got := identity.KeyIDOf(carried, prof); hex.EncodeToString(got[:]) != k.KeyID {
				t.Errorf("%s %s: key id %x, want %s", name, keyName, got, k.KeyID)
			}
			if k.NodeID != "" {
				if got := identity.NodeIDOf(carried, prof); hex.EncodeToString(got[:]) != k.NodeID {
					t.Errorf("%s %s: node_id %x, want %s", name, keyName, got, k.NodeID)
				}
			}
		}
	}
}

func TestVectorsCovers(t *testing.T) {
	v := loadVectors(t)
	for _, c := range v.Covers {
		if got := Covers(c.Parent, c.Child); got != c.Covers {
			t.Errorf("Covers(%q, %q) = %v, macula's is %v", c.Parent, c.Child, got, c.Covers)
		}
	}
}
