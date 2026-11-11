package ucan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// FuzzParsed and FuzzAuthorize hold the token reader to macula-go#39's
// invariant on any byte string a peer can present: a token whose claims are
// read, or a refusal carrying one of macula_ucan's refusals -- never a panic,
// and never a token read past its bounds.
//
// FuzzParsed feeds a token as it arrives on the wire, and holds the decoder's
// own promise: the bytes a signature covers are the token's first two segments
// as presented, and nothing else. FuzzAuthorize fuzzes a token's header and
// claims bytes and signs them with a test key, so every input is a token that
// gets past decoding, the signature and the audience: the capability, chain and
// walk checks are what it exercises, which is where an SDK reads what it was
// granted. TestFuzzedSeedsReachTheGrants shows that those checks are reached,
// rather than assuming it.
//
// The seed corpus is every token of the shared UCAN vectors
// (ucan/testdata/ucan_v1.json, macula's test/vectors/ucan_v1.json), read from
// the file rather than restated: as whole tokens for FuzzParsed, and as the
// header and claims they carry for FuzzAuthorize.
//
// A hang is the package test timeout: a token is three dot-separated parts,
// each decoded into a bounded JSON object, and the only expensive step (the
// ML-DSA signature) runs once per token.

// fuzzVectors is the fields of ucan_v1.json the fuzzers seed from.
type fuzzVectors struct {
	Profiles map[string]struct {
		Cases []struct {
			Token string `json:"token"`
			// Context carries the clock the case was written for.
			Context struct {
				Now int64 `json:"now"`
			} `json:"context"`
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
			now = max(now, c.Context.Now)
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
		t.Fatalf("the vector file holds no tokens")
	}
	return tokens, now
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
		signed := append(append([]byte{}, parts[0]...), append([]byte("."), parts[1]...)...)
		if !bytes.Equal(parsedToken.input, signed) {
			t.Fatalf("the signed input is not the token's first two segments: %q", parsedToken.input)
		}
	})
}

// FuzzAuthorize fuzzes a token's header and claims bytes, signed with the
// fixture's key, and presents it to its audience with the token itself among the
// proofs.
func FuzzAuthorize(f *testing.F) {
	fixture := newFuzzToken(f)
	for _, seed := range fixture.seeds(f) {
		f.Add(seed.header, seed.claims)
	}
	f.Fuzz(func(t *testing.T, header, claims []byte) {
		token := signedSegment(t, fixture.issuer, header, claims)
		if _, err := Authorize(token, fixture.policy, fixture.context()); err != nil {
			refusalAsOneOf(t, err)
		}
	})
}

// fuzzToken is what a fuzzed token is signed by and presented to: a test key as
// issuer, its own policy, and the context of its audience.
type fuzzToken struct {
	issuer  *identity.NodeKey
	policy  UCANRequired
	request *Request
	now     int64
	caller  [32]byte
}

func newFuzzToken(t testing.TB) fuzzToken {
	t.Helper()
	issuer := teststation.Key(t, profile.PQPure, "ucan fuzz issuer")
	audience := teststation.Key(t, profile.PQPure, "ucan fuzz audience")
	caller, err := audience.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	issuerNode, err := issuer.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	// The vectors' own clock: their tokens are minted around it, so a token
	// this fixture signs at it is valid in the same window.
	_, now := fuzzTokens(t)
	return fuzzToken{
		issuer:  issuer,
		policy:  UCANRequired{Issuer: issuerNode},
		request: &Request{Realm: sha256.Sum256([]byte("io.macula")), Procedure: fuzzProcedure},
		now:     now,
		caller:  caller,
	}
}

const fuzzProcedure = "acme/count_v1"

// context is the token presented by the audience it names, with the tokens in
// proofs beside it, keyed as a chain names them. A token whose claims name none
// of them is refused for it (unreferenced_proof), which is the rule for a proof
// nobody used: the fuzzer supplies one only where the seed has a chain.
func (f fuzzToken) context(proofs ...[]byte) Context {
	ids := make(map[string][]byte, len(proofs))
	for _, proof := range proofs {
		ids[ProofID(proof)] = proof
	}
	return Context{Caller: f.caller, Profile: profile.PQPure, Now: f.now, Request: f.request, Proofs: ids}
}

// claims is a claims object for this fixture: issued by the fixture's issuer to
// its audience, valid at now, carrying what extra gives.
func (f fuzzToken) claims(t testing.TB, extra map[string]any) []byte {
	t.Helper()
	claims := map[string]any{
		"iss": DIDKey(f.issuer.PublicKey(), f.issuer.Profile()),
		"aud": hex.EncodeToString(f.caller[:]),
		"cap": []Capability{{With: "mri:proc:io.macula/acme/count_v1", Can: "invoke"}},
		"exp": f.now + 3600,
	}
	for name, value := range extra {
		claims[name] = value
	}
	out, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// header is the header this fixture's profile signs with.
func (f fuzzToken) header(t testing.TB) []byte {
	t.Helper()
	algorithm, err := alg(f.issuer.Profile())
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(map[string]string{"alg": algorithm, "typ": typ, "ucv": ucv})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// signedSegment is the token over exactly these header and claims bytes, signed
// by issuer as macula_ucan signs one: the two segments one dot apart, and the
// signature over them.
func signedSegment(t testing.TB, issuer *identity.NodeKey, header, claims []byte) []byte {
	t.Helper()
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	signature, err := issuer.Sign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
}

// fuzzSeed is one seed of FuzzAuthorize: the bytes it fuzzes, and the proofs
// that go beside the token so a chain can be walked.
type fuzzSeed struct {
	header, claims []byte
	proofs         [][]byte
}

// seeds is the corpus FuzzAuthorize starts from: the vectors' own tokens and
// claims, and the claims of this fixture that get a token past the signature,
// the audience and the clock into the capability and chain checks.
func (f fuzzToken) seeds(t testing.TB) []fuzzSeed {
	t.Helper()
	header := f.header(t)
	out := []fuzzSeed{
		// The fixture's own token: it authorizes, so the grants and the chain
		// both run.
		{header: header, claims: f.claims(t, nil)},
		// A capability that does not cover the request: the grants check runs
		// and refuses.
		{header: header, claims: f.claims(t, map[string]any{
			"cap": []Capability{{With: "mri:realm:io.macula", Can: "invoke"}},
		})},
	}
	parent := signedSegment(t, f.issuer, header, f.claims(t, nil))
	// A chain whose parent is beside it, and one whose parent is missing: the
	// walk runs, and reaches the delegation and narrowing checks or the proof
	// lookup.
	out = append(out,
		fuzzSeed{header: header, claims: f.claims(t, map[string]any{"prf": []string{ProofID(parent)}}), proofs: [][]byte{parent}},
		fuzzSeed{header: header, claims: f.claims(t, map[string]any{"prf": []string{ProofID(parent)}})},
		// The vectors' own tokens, as the header and claims they carry.
	)
	for _, token := range fuzzVectorSegments(t) {
		out = append(out, fuzzSeed{header: token[0], claims: token[1]})
	}
	return out
}

// fuzzVectorSegments is every vector token's header and claims, decoded from the
// base64 the JWT carries. A token whose segments do not decode is passed over:
// the fuzzers seed from what the vectors hold, and a broken one is FuzzParsed's.
func fuzzVectorSegments(t testing.TB) [][2][]byte {
	t.Helper()
	tokens, _ := fuzzTokens(t)
	var out [][2][]byte
	for _, token := range tokens {
		parts := bytes.Split(token, []byte("."))
		if len(parts) != 3 {
			continue
		}
		header, err := base64.RawURLEncoding.DecodeString(string(parts[0]))
		if err != nil {
			continue
		}
		claims, err := base64.RawURLEncoding.DecodeString(string(parts[1]))
		if err != nil {
			continue
		}
		out = append(out, [2][]byte{header, claims})
	}
	return out
}

// deepRefusals are the refusals only the capability, chain and walk checks give:
// an input that reaches one of them, or that authorizes, has been read for what
// it grants.
var deepRefusals = []error{
	ErrMissingCapability,
	ErrMissingProof,
	ErrUnreferencedProof,
	ErrNotTheDelegate,
	ErrChainNotLinear,
	ErrGrantsMoreThanProof,
	ErrCanChanged,
	ErrWrongRealm,
	ErrProcedureWithoutOrg,
}

// chainRefusals are the refusals only the walk gives, once a token names a
// parent.
var chainRefusals = []error{
	ErrMissingProof,
	ErrUnreferencedProof,
	ErrNotTheDelegate,
	ErrChainNotLinear,
	ErrGrantsMoreThanProof,
	ErrCanChanged,
}

// reachedTheChainWalk is whether an outcome means a token's chain was walked.
func reachedTheChainWalk(err error) bool {
	for _, refusal := range chainRefusals {
		if errors.Is(err, refusal) {
			return true
		}
	}
	return false
}

// reachedTheGrants is whether an outcome means the capability and chain checks
// ran: an authorization, or one of their refusals.
func reachedTheGrants(err error) bool {
	if err == nil {
		return true
	}
	for _, refusal := range deepRefusals {
		if errors.Is(err, refusal) {
			return true
		}
	}
	return false
}

// TestFuzzedSeedsReachTheGrants shows what FuzzAuthorize's seeds cover: a seed
// that authorizes, so the grants and chain run to the end; and a seed whose
// chain is walked, so a delegated token's parent is read too. Without this the
// target would only re-test the decoder with extra steps.
func TestFuzzedSeedsReachTheGrants(t *testing.T) {
	fixture := newFuzzToken(t)
	authorized, walked := 0, 0
	for _, seed := range fixture.seeds(t) {
		token := signedSegment(t, fixture.issuer, seed.header, seed.claims)
		_, err := Authorize(token, fixture.policy, fixture.context(seed.proofs...))
		if err != nil && !reachedTheGrants(err) {
			continue
		}
		authorized++
		if reachedTheChainWalk(err) {
			walked++
		}
	}
	if authorized == 0 {
		t.Fatalf("no seed reached the grants: the target only exercises the decoder")
	}
	if walked == 0 {
		t.Fatalf("no seed reached the chain walk")
	}
	t.Logf("seeds reaching the grants: %d, of them through a chain walk: %d", authorized, walked)
}

// refusalAsOneOf fails t unless err is one of macula_ucan's refusals, or the
// refusal a binary without ML-DSA gives before it reads anything.
func refusalAsOneOf(t *testing.T, err error) {
	t.Helper()
	if RefusalName(err) != "" || errors.Is(err, identity.ErrPostQuantumUnavailable) {
		return
	}
	t.Fatalf("refused with an error that is not a refusal: %v", err)
}
