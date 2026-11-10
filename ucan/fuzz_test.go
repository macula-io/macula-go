package ucan

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// FuzzParsed and FuzzAuthorize hold the token decoder to macula-go#39's
// invariant on any byte string a peer can present: either it decodes to a token
// whose claims are read the same way twice, or it is refused with one of
// macula_ucan's refusals -- never a panic, and never a token read past its
// bounds. The seed corpus is every token of the shared UCAN vectors
// (ucan/testdata/ucan_v1.json, macula's test/vectors/ucan_v1.json), read from
// the file rather than restated here.
//
// A hang is the package test timeout: a token is three dot-separated parts,
// each decoded into a bounded JSON object, and the only expensive step (the
// ML-DSA signature) runs once per token.
//
// FuzzAuthorize authorizes against a policy no token can satisfy, so its inputs
// walk the whole reading path -- the header, the DID key, the signature, the
// capabilities -- without ever needing a key to sign with.

// fuzzVectors is the fields of ucan_v1.json the fuzzers seed from.
type fuzzVectors struct {
	Profiles map[string]struct {
		Cases []struct {
			Token string `json:"token"`
		} `json:"cases"`
		ProofIDs []struct {
			Token string `json:"token"`
		} `json:"proof_ids"`
	} `json:"profiles"`
}

// fuzzTokens is every distinct token the vector file holds, and the latest time
// its cases are checked at.
func fuzzTokens(t testing.TB) (tokens [][]byte, now int64) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "ucan_v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v fuzzVectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, p := range v.Profiles {
		var texts []string
		for _, c := range p.Cases {
			texts = append(texts, c.Token)
		}
		for _, id := range p.ProofIDs {
			texts = append(texts, id.Token)
		}
		for _, text := range texts {
			if seen[text] {
				continue
			}
			seen[text] = true
			tokens = append(tokens, []byte(text))
		}
	}
	if len(tokens) == 0 {
		t.Fatal("the vector file holds no tokens")
	}
	// The cases' own clock: tokens are minted around it, so authorizing at it
	// is what exercises the success paths rather than only the time refusals.
	now = fuzzVectorNow(t, raw)
	return tokens, now
}

func fuzzVectorNow(t testing.TB, raw []byte) int64 {
	t.Helper()
	var v struct {
		Profiles map[string]struct {
			Cases []struct {
				Context struct {
					Now int64 `json:"now"`
				} `json:"context"`
			} `json:"cases"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	var latest int64
	for _, p := range v.Profiles {
		for _, c := range p.Cases {
			latest = max(latest, c.Context.Now)
		}
	}
	return latest
}

// FuzzParsed holds the token decoder to the invariant: a token, or a refusal.
func FuzzParsed(f *testing.F) {
	tokens, _ := fuzzTokens(f)
	for _, token := range tokens {
		f.Add(token)
	}
	f.Fuzz(func(t *testing.T, token []byte) {
		parsedToken, err := parsed(token)
		if err != nil {
			refusalAsOneOf(t, err)
			return
		}
		if parsedToken.claims == nil || parsedToken.header == nil {
			t.Fatalf("a parsed token without its header or claims")
		}
		// The bytes a signature covers are the two segments as presented, and
		// nothing else: what is verified is what arrived.
		parts := bytes.Split(token, []byte("."))
		if !bytes.Equal(parsedToken.input, append(append([]byte{}, parts[0]...), append([]byte("."), parts[1]...)...)) {
			t.Fatalf("the signed input is not the token's first two segments: %q", parsedToken.input)
		}
	})
}

// FuzzAuthorize holds the whole reading path to the invariant: claims, or a
// refusal. The policy is one no token satisfies, so a success would itself be a
// finding.
func FuzzAuthorize(f *testing.F) {
	tokens, now := fuzzTokens(f)
	for _, token := range tokens {
		f.Add(token)
	}
	policy := noTokenAuthorizes{}
	f.Fuzz(func(t *testing.T, token []byte) {
		if err := identity.CheckPostQuantum(); err != nil {
			t.Skip("no ML-DSA in this binary: nothing is read to authorize")
		}
		claims, err := Authorize(token, policy, Context{Profile: profile.PQHybrid, Now: now, Proofs: map[string][]byte{}})
		if err != nil {
			refusalAsOneOf(t, err)
			return
		}
		t.Fatalf("authorized under a policy no token names: %v", claims)
	})
}

// noTokenAuthorizes is a policy whose chain can never be rooted: it names the
// issuer key id of no token.
type noTokenAuthorizes struct{ UCANRequired }

// refusalAsOneOf fails t unless err is one of macula_ucan's refusals, or the
// refusal a binary without ML-DSA gives before it reads anything.
func refusalAsOneOf(t *testing.T, err error) {
	t.Helper()
	if RefusalName(err) != "" || errors.Is(err, identity.ErrPostQuantumUnavailable) {
		return
	}
	t.Fatalf("refused with an error that is not a refusal: %v", err)
}
