package ucan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
)

func mustIdentity(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func ptr(i int64) *int64 { return &i }

func TestCreateVerifyRoundTrip(t *testing.T) {
	issuerID := mustIdentity(t)
	caps := []Capability{{With: "mri:mailbox:example", Can: "deposit_letter"}}
	token, err := Create("did:macula:issuer", "did:macula:audience", caps, issuerID, CreateOpts{
		ExpiresAt: ptr(time.Now().Add(time.Hour).Unix()),
		Nonce:     "abc123",
		Proofs:    []string{"parentcid1"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d dot-separated parts, want 3 (JWT-shaped)", len(parts))
	}

	payload, err := Verify(token, issuerID.NodeID())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if payload.Issuer != "did:macula:issuer" {
		t.Errorf("Issuer = %q, want did:macula:issuer", payload.Issuer)
	}
	if payload.Audience != "did:macula:audience" {
		t.Errorf("Audience = %q, want did:macula:audience", payload.Audience)
	}
	if payload.Nonce != "abc123" {
		t.Errorf("Nonce = %q, want abc123", payload.Nonce)
	}
	if len(payload.Capabilities) != 1 || payload.Capabilities[0] != caps[0] {
		t.Errorf("Capabilities = %+v, want %+v", payload.Capabilities, caps)
	}
	if len(payload.Proofs) != 1 || payload.Proofs[0] != "parentcid1" {
		t.Errorf("Proofs = %+v, want [parentcid1]", payload.Proofs)
	}
}

func TestHeaderMatchesReferenceExactly(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	headerB64 := strings.Split(string(token), ".")[0]
	raw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h map[string]string
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if h["alg"] != "EdDSA" || h["typ"] != "JWT" || h["ucv"] != "0.10.0" {
		t.Fatalf("header = %+v, want alg=EdDSA typ=JWT ucv=0.10.0 (macula_ucan_nif's exact wire header)", h)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", []Capability{{With: "a", Can: "b"}}, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	parts := strings.Split(string(token), ".")
	payloadRaw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var p wirePayload
	_ = json.Unmarshal(payloadRaw, &p)
	p.Capabilities[0].Can = "delete_everything" // tamper after signing
	tamperedJSON, _ := json.Marshal(p)
	tampered := parts[0] + "." + base64.RawURLEncoding.EncodeToString(tamperedJSON) + "." + parts[2]

	if _, err := Verify([]byte(tampered), id.NodeID()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(tampered) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongSigner(t *testing.T) {
	issuerID := mustIdentity(t)
	otherID := mustIdentity(t)
	token, err := Create("iss", "aud", nil, issuerID, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, otherID.NodeID()); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Verify(wrong signer) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsExpiredToken(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{ExpiresAt: ptr(time.Now().Add(-time.Hour).Unix())})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, id.NodeID()); !errors.Is(err, ErrExpired) {
		t.Fatalf("Verify(expired) = %v, want ErrExpired", err)
	}
}

func TestVerifyRejectsNotYetValidToken(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{NotBefore: ptr(time.Now().Add(time.Hour).Unix())})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, id.NodeID()); !errors.Is(err, ErrNotYetValid) {
		t.Fatalf("Verify(not yet valid) = %v, want ErrNotYetValid", err)
	}
}

func TestVerifyAcceptsTokenWithNoExpiryOrNbf(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, id.NodeID()); err != nil {
		t.Fatalf("Verify(no exp/nbf) = %v, want nil (absent claims never fail)", err)
	}
}

func TestVerifyRejectsInvalidPublicKey(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, []byte("too-short")); !errors.Is(err, ErrInvalidPublicKey) {
		t.Fatalf("Verify(bad pubkey) = %v, want ErrInvalidPublicKey", err)
	}
}

func TestVerifyRejectsMalformedToken(t *testing.T) {
	id := mustIdentity(t)
	if _, err := Verify([]byte("not.a.valid.jwt.shape"), id.NodeID()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(malformed) = %v, want ErrInvalidToken", err)
	}
	if _, err := Verify([]byte("onlyonepart"), id.NodeID()); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("Verify(one part) = %v, want ErrInvalidToken", err)
	}
}

// Decode does NOT check the signature at all -- confirmed against the
// reference (macula_ucan_nif:decode/1's own doc: "WARNING: This does NOT
// verify the signature!"). A token "signed" by an unrelated identity (or
// garbage bytes as the signature) still decodes successfully.
func TestDecodeDoesNotVerifySignature(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("untrusted-issuer", "aud", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	parts := strings.Split(string(token), ".")
	garbageSig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature-at-all"))
	corrupted := parts[0] + "." + parts[1] + "." + garbageSig

	payload, err := Decode([]byte(corrupted))
	if err != nil {
		t.Fatalf("Decode should succeed despite a garbage signature: %v", err)
	}
	if payload.Issuer != "untrusted-issuer" {
		t.Fatalf("Decode payload.Issuer = %q, want untrusted-issuer", payload.Issuer)
	}
}

// Verify does NOT check the audience field at all -- confirmed against
// the reference (macula_station_link.erl's check_ucan/2 and
// macula_ucan_nif's verify/2 only ever check signature/exp/nbf; audience
// matching, if a caller wants it, is the caller's own responsibility via
// GetAudience/Payload.Audience after a successful Verify).
func TestVerifyDoesNotCheckAudience(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "someone-else-entirely", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := Verify(token, id.NodeID()); err != nil {
		t.Fatalf("Verify should not reject on audience mismatch (that's a caller-side check): %v", err)
	}
}

func TestAccessors(t *testing.T) {
	id := mustIdentity(t)
	exp := ptr(time.Now().Add(time.Hour).Unix())
	caps := []Capability{{With: "mri:x", Can: "y"}}
	token, err := Create("the-issuer", "the-audience", caps, id, CreateOpts{
		ExpiresAt: exp, Proofs: []string{"cid-a", "cid-b"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if iss, err := GetIssuer(token); err != nil || iss != "the-issuer" {
		t.Errorf("GetIssuer = %q, %v, want the-issuer, nil", iss, err)
	}
	if aud, err := GetAudience(token); err != nil || aud != "the-audience" {
		t.Errorf("GetAudience = %q, %v, want the-audience, nil", aud, err)
	}
	if gotCaps, err := GetCapabilities(token); err != nil || len(gotCaps) != 1 || gotCaps[0] != caps[0] {
		t.Errorf("GetCapabilities = %+v, %v, want %+v, nil", gotCaps, err, caps)
	}
	if gotExp, err := GetExpiration(token); err != nil || gotExp == nil || *gotExp != *exp {
		t.Errorf("GetExpiration = %v, %v, want %d", gotExp, err, *exp)
	}
	if proofs, err := GetProofs(token); err != nil || len(proofs) != 2 || proofs[0] != "cid-a" || proofs[1] != "cid-b" {
		t.Errorf("GetProofs = %+v, %v, want [cid-a cid-b]", proofs, err)
	}
}

func TestIsExpired(t *testing.T) {
	id := mustIdentity(t)

	noExp, _ := Create("iss", "aud", nil, id, CreateOpts{})
	if exp, err := IsExpired(noExp); err != nil || exp {
		t.Errorf("IsExpired(no exp claim) = %v, %v, want false, nil", exp, err)
	}

	future, _ := Create("iss", "aud", nil, id, CreateOpts{ExpiresAt: ptr(time.Now().Add(time.Hour).Unix())})
	if exp, err := IsExpired(future); err != nil || exp {
		t.Errorf("IsExpired(future exp) = %v, %v, want false, nil", exp, err)
	}

	past, _ := Create("iss", "aud", nil, id, CreateOpts{ExpiresAt: ptr(time.Now().Add(-time.Hour).Unix())})
	if exp, err := IsExpired(past); err != nil || !exp {
		t.Errorf("IsExpired(past exp) = %v, %v, want true, nil", exp, err)
	}
}

// ComputeCID matches macula_ucan_nif:compute_cid/1's exact scheme:
// base64url-no-pad(sha256(raw token bytes)) -- verified here against a
// from-scratch computation using stdlib only, independent of this
// package's own crypto/sha256 import, to catch a copy-paste bug that
// would otherwise pass against itself trivially.
func TestComputeCIDMatchesReferenceScheme(t *testing.T) {
	id := mustIdentity(t)
	token, err := Create("iss", "aud", nil, id, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	got := ComputeCID(token)

	h := sha256.Sum256(token)
	want := base64.RawURLEncoding.EncodeToString(h[:])
	if got != want {
		t.Fatalf("ComputeCID = %q, want %q", got, want)
	}
	// Deterministic: same token, same CID, every time.
	if again := ComputeCID(token); again != got {
		t.Fatalf("ComputeCID not deterministic: %q vs %q", got, again)
	}
}

func TestPolicyOpenAlwaysPasses(t *testing.T) {
	if err := Open.Check(nil); err != nil {
		t.Fatalf("Open.Check(nil) = %v, want nil", err)
	}
	if err := Open.Check([]byte("anything, ignored")); err != nil {
		t.Fatalf("Open.Check(token) = %v, want nil (open ignores tokens entirely)", err)
	}
}

func TestPolicyRequiredAcceptsValidToken(t *testing.T) {
	issuerID := mustIdentity(t)
	callerID := mustIdentity(t)
	token, err := Create(
		"did:macula:"+encodeHex(issuerID.NodeID()),
		"did:macula:"+encodeHex(callerID.NodeID()),
		[]Capability{{With: "mri:mailbox:x", Can: "deposit_letter"}},
		issuerID, CreateOpts{ExpiresAt: ptr(time.Now().Add(time.Hour).Unix())},
	)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	policy := Required(issuerID.NodeID())
	if err := policy.Check(token); err != nil {
		t.Fatalf("Required(issuer).Check(valid token) = %v, want nil", err)
	}
}

func TestPolicyRequiredRejectsMissingToken(t *testing.T) {
	issuerID := mustIdentity(t)
	policy := Required(issuerID.NodeID())
	if err := policy.Check(nil); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Required(issuer).Check(nil) = %v, want ErrNoToken", err)
	}
	if err := policy.Check([]byte{}); !errors.Is(err, ErrNoToken) {
		t.Fatalf("Required(issuer).Check(empty) = %v, want ErrNoToken", err)
	}
}

func TestPolicyRequiredRejectsTokenFromWrongIssuer(t *testing.T) {
	requiredIssuerID := mustIdentity(t)
	actualSignerID := mustIdentity(t)
	token, err := Create("iss", "aud", nil, actualSignerID, CreateOpts{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	policy := Required(requiredIssuerID.NodeID())
	if err := policy.Check(token); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("Required(issuer).Check(token from a different signer) = %v, want ErrInvalidSignature", err)
	}
}

func encodeHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexdigits[c>>4]
		out[i*2+1] = hexdigits[c&0x0f]
	}
	return string(out)
}
