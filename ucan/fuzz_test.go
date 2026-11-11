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

// FuzzAuthorize fuzzes a token's header and claims bytes, signed by the
// fixture's delegate, and presents it to its audience with the delegate's parent
// beside it as a proof. A claims block that names that parent's id is walked up
// it, so the delegation checks run on fuzzed bytes; one that does not is refused
// for the unused proof.
func FuzzAuthorize(f *testing.F) {
	fixture := newFuzzToken(f)
	for _, seed := range fixture.seeds(f) {
		f.Add(seed.header, seed.claims)
	}
	f.Fuzz(func(t *testing.T, header, claims []byte) {
		if _, err := fixture.authorize(t, header, claims); err != nil {
			refusalAsOneOf(t, err)
		}
	})
}

// fuzzToken is what a fuzzed token is signed by and presented to: the delegate
// key signs it, the delegate's parent is the policy's issuer, and the context is
// the audience's. The two keys are what make a chain walkable: a token signed by
// a key nobody delegates to would be refused before the delegation checks ran.
// root is the parent, signed once, because a proof is named by the hash of a
// token and a second signing of it would carry another hash.
type fuzzToken struct {
	issuer   *identity.NodeKey
	delegate *identity.NodeKey
	policy   UCANRequired
	request  *Request
	now      int64
	caller   [32]byte
	root     []byte
}

func newFuzzToken(t testing.TB) fuzzToken {
	t.Helper()
	issuer := teststation.Key(t, profile.PQPure, "ucan fuzz issuer")
	delegate := teststation.Key(t, profile.PQPure, "ucan fuzz delegate")
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
	f := fuzzToken{
		issuer:   issuer,
		delegate: delegate,
		policy:   UCANRequired{Issuer: issuerNode},
		request:  &Request{Realm: sha256.Sum256([]byte(fuzzRealm)), Procedure: fuzzProcedure},
		now:      now,
		caller:   caller,
	}
	f.root = f.signRoot(t)
	return f
}

const (
	fuzzProcedure = "acme/count_v1"
	fuzzRealm     = "io.macula"
	// fuzzWith is the grant the fixture's tokens carry: the procedure above, in
	// the realm the request names.
	fuzzWith = "mri:proc:" + fuzzRealm + "/" + fuzzProcedure
)

// authorize is how a fuzzed header and claims are judged: a token over exactly
// those bytes, signed by the delegate, presented to the audience with root
// beside it. FuzzAuthorize and TestFuzzedSeedsReachTheGrants judge a seed through
// this one function, so what the seed test reports is what the target runs.
func (f fuzzToken) authorize(t testing.TB, header, claims []byte) (map[string]any, error) {
	t.Helper()
	return Authorize(signedSegment(t, f.delegate, header, claims), f.policy, f.context(f.root))
}

// context is the token presented by the audience it names, with the proofs the
// chain names beside it, keyed as a chain names them. A proof nobody names is
// refused for it (unreferenced_proof), so a token without a chain carries none.
func (f fuzzToken) context(proofs ...[]byte) Context {
	ids := make(map[string][]byte, len(proofs))
	for _, proof := range proofs {
		ids[ProofID(proof)] = proof
	}
	return Context{Caller: f.caller, Profile: profile.PQPure, Now: f.now, Request: f.request, Proofs: ids}
}

// claims is a claims object for this fixture: issued by the delegate to its
// audience, valid at now, carrying what extra gives.
func (f fuzzToken) claims(t testing.TB, extra map[string]any) []byte {
	t.Helper()
	claims := map[string]any{
		"iss": DIDKey(f.delegate.PublicKey(), f.delegate.Profile()),
		"aud": hex.EncodeToString(f.caller[:]),
		"cap": []Capability{{With: fuzzWith, Can: "invoke"}},
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

// signRoot is the token above a fuzzed one: the policy's issuer granting the
// delegate the procedure the fixture's claims carry, so a chain from the
// delegate up to the issuer can be walked.
func (f fuzzToken) signRoot(t testing.TB) []byte {
	t.Helper()
	delegate, err := f.delegate.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	claims := f.claims(t, map[string]any{
		"iss": DIDKey(f.issuer.PublicKey(), f.issuer.Profile()),
		"aud": hex.EncodeToString(delegate[:]),
	})
	return signedSegment(t, f.issuer, f.header(t), claims)
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

// fuzzSeed is one seed of FuzzAuthorize: the header and claims bytes it fuzzes,
// and whether those claims name a proof, so the seed test can say which seeds
// go through the walk.
type fuzzSeed struct {
	header, claims []byte
	chained        bool
}

// seeds is the corpus FuzzAuthorize starts from: the vectors' own tokens and
// claims, and the claims of this fixture that get a token past the signature,
// the audience and the clock into the capability and chain checks. The chained
// seeds name the root's id, so the walk runs on every push and not only under a
// -fuzz run: a fuzzer whose seeds never name a proof spends the run refusing at
// the proof lookup.
func (f fuzzToken) seeds(t testing.TB) []fuzzSeed {
	t.Helper()
	header := f.header(t)
	root := f.root
	out := []fuzzSeed{
		// The fixture's own token, naming no proof: the grants check runs, and
		// the walk finds a token nobody delegated to.
		{header: header, claims: f.claims(t, nil)},
		// A capability that does not cover the request: the grants check runs
		// and refuses.
		{header: header, claims: f.claims(t, map[string]any{
			"cap": []Capability{{With: "mri:realm:" + fuzzRealm, Can: "invoke"}},
		})},
		// The chained token: it names the root as its proof, so the walk runs
		// from the delegate up to the issuer and the delegation checks decide.
		{header: header, claims: f.claims(t, map[string]any{"prf": []string{ProofID(root)}}), chained: true},
		// A chained token that hands on more than the root granted: the
		// narrowing check runs and refuses.
		{header: header, claims: f.claims(t, map[string]any{
			"cap": []Capability{{With: "mri:realm:" + fuzzRealm, Can: "invoke"}},
			"prf": []string{ProofID(root)},
		}), chained: true},
		// A chained token naming a proof nobody supplies: the lookup runs, and
		// the token is refused for the missing proof.
		{header: header, claims: f.claims(t, map[string]any{
			"prf": []string{ProofID([]byte("a token nobody supplies"))},
		}), chained: true},
		// The vectors' own tokens, as the header and claims they carry.
	}
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
// target would only re-test the decoder with extra steps. A seed is judged
// through the same authorize the target runs, so the count is about what a push
// actually does.
func TestFuzzedSeedsReachTheGrants(t *testing.T) {
	fixture := newFuzzToken(t)
	authorized, walked, delegated := 0, 0, 0
	for _, seed := range fixture.seeds(t) {
		_, err := fixture.authorize(t, seed.header, seed.claims)
		if seed.chained && err == nil {
			delegated++
		}
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
	if delegated == 0 {
		t.Fatalf("no seed authorized through its chain: the delegation checks decide nothing")
	}
	t.Logf("seeds reaching the grants: %d, of them through a chain walk: %d, of them authorizing through a chain: %d",
		authorized, walked, delegated)
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
