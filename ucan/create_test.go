package ucan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

func nodeOf(t *testing.T, k *identity.NodeKey) [32]byte {
	t.Helper()
	id, err := k.NodeID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Tokens this package mints authorize as macula's do: a root token, and a
// delegated chain whose proof travels beside it; and each check refuses them
// when it should.
func TestCreatedTokensAuthorize(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			root := teststation.Key(t, p, "ucan root")
			alice := teststation.Key(t, p, "ucan alice")
			bob := teststation.Key(t, p, "ucan bob")
			const now = int64(1790000000)
			request := &Request{Realm: sha256.Sum256([]byte("io.macula")), Procedure: "acme/count_v1"}
			policy := UCANRequired{Issuer: nodeOf(t, root)}

			toAlice, err := Create(root, nodeOf(t, alice), []Capability{{With: "mri:org:io.macula/acme", Can: "invoke"}},
				Options{Exp: now + 3600})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(toAlice), ".") || strings.Count(string(toAlice), ".") != 2 {
				t.Fatalf("not a JWT: %.60s", toAlice)
			}
			ctx := Context{Caller: nodeOf(t, alice), Profile: p, Now: now, Request: request}
			if _, err := Authorize(toAlice, policy, ctx); err != nil {
				t.Fatalf("a root token: %v", err)
			}

			toBob, err := Create(alice, nodeOf(t, bob), []Capability{{With: "mri:proc:io.macula/acme/count_v1", Can: "invoke"}},
				Options{Exp: now + 60, Prf: []string{ProofID(toAlice)}})
			if err != nil {
				t.Fatal(err)
			}
			chain := Context{Caller: nodeOf(t, bob), Profile: p, Now: now, Request: request,
				Proofs: map[string][]byte{ProofID(toAlice): toAlice}}
			if _, err := Authorize(toBob, policy, chain); err != nil {
				t.Fatalf("a delegated chain: %v", err)
			}

			for name, c := range map[string]struct {
				ctx  Context
				want error
			}{
				"presented by another node": {Context{Caller: nodeOf(t, bob), Profile: p, Now: now, Request: request}, ErrNotTheAudience},
				"at its exp":                {Context{Caller: nodeOf(t, alice), Profile: p, Now: now + 3600, Request: request}, ErrExpired},
				"for another procedure": {Context{Caller: nodeOf(t, alice), Profile: p, Now: now,
					Request: &Request{Realm: request.Realm, Procedure: "beta/count_v1"}}, ErrMissingCapability},
			} {
				if _, err := Authorize(toAlice, policy, c.ctx); !errors.Is(err, c.want) {
					t.Errorf("%s: %v, want %v", name, err, c.want)
				}
			}
			if _, err := Authorize(toBob, policy, Context{Caller: nodeOf(t, bob), Profile: p, Now: now, Request: request}); !errors.Is(err, ErrMissingProof) {
				t.Errorf("a chain without its proof: %v, want missing_proof", err)
			}
		})
	}
}

func TestCreateRefusesAKeyThatIsNotAnIdentityKey(t *testing.T) {
	connect, err := identity.GenerateKey(identity.PurposeConnect, profile.PQPure)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Create(connect, [32]byte{}, nil, Options{Exp: 1}); err == nil {
		t.Fatal("a CONNECT key minted a token")
	}
}

// An expiry is seconds. One in milliseconds, or more than MaxLifetime past
// now, is refused at minting, as is a window that never opens; each refusal
// names both values. A token for a year is minted.
func TestCreateRefusesAnAbsurdWindow(t *testing.T) {
	root := teststation.Key(t, profile.PQPure, "ucan bounds")
	now := time.Now().Unix()
	year := now + 366*24*3600
	early, late := now+120, now+60
	for name, c := range map[string]struct {
		o     Options
		want  error
		names []int64
	}{
		"an exp in milliseconds":       {Options{Exp: time.Now().UnixMilli() + 3_600_000}, ErrExpBeyondMaxLifetime, nil},
		"an exp just past MaxLifetime": {Options{Exp: now + MaxLifetime + 60}, ErrExpBeyondMaxLifetime, []int64{now + MaxLifetime + 60}},
		"an nbf after its exp":         {Options{Exp: late, Nbf: &early}, ErrWindowNeverOpens, []int64{early, late}},
		"an nbf at its exp":            {Options{Exp: late, Nbf: &late}, ErrWindowNeverOpens, []int64{late}},
	} {
		_, err := Create(root, [32]byte{}, nil, c.o)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
			continue
		}
		for _, v := range append(c.names, c.o.Exp) {
			if !strings.Contains(err.Error(), strconv.FormatInt(v, 10)) {
				t.Errorf("%s: %q does not name %d", name, err, v)
			}
		}
	}
	nbf := now
	for name, o := range map[string]Options{
		"a year":                {Exp: year},
		"a year, from now":      {Exp: year, Nbf: &nbf},
		"just inside the bound": {Exp: now + MaxLifetime - 60},
	} {
		if _, err := Create(root, [32]byte{}, nil, o); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// signedClaims is a token from issuer to audience with these claims over one
// capability, minted past Create's checks, as an older SDK could have minted
// it.
func signedClaims(t *testing.T, issuer *identity.NodeKey, audience [32]byte, claims map[string]any) []byte {
	t.Helper()
	algorithm, err := alg(issuer.Profile())
	if err != nil {
		t.Fatal(err)
	}
	claims["iss"] = DIDKey(issuer.PublicKey(), issuer.Profile())
	claims["aud"] = hex.EncodeToString(audience[:])
	claims["cap"] = []Capability{{With: "mri:realm:io.macula", Can: "invoke"}}
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "typ": typ, "ucv": ucv})
	payload, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature, err := issuer.Sign([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature))
}

// UCAN_V1 has no revocation, so a token's exp is the only bound on its life.
// Authorize refuses an exp more than MaxLifetime past now, whoever minted it,
// as macula_ucan does, and the refusal names the exp and now it compared. An
// exp at the bound is valid.
func TestAuthorizeRefusesAnExpBeyondMaxLifetime(t *testing.T) {
	root := teststation.Key(t, profile.PQPure, "ucan lifetime root")
	alice := teststation.Key(t, profile.PQPure, "ucan lifetime alice")
	const now = int64(1790000000)
	policy := UCANRequired{Issuer: nodeOf(t, root)}
	ctx := Context{Caller: nodeOf(t, alice), Profile: profile.PQPure, Now: now}
	authorize := func(claims map[string]any) error {
		_, err := Authorize(signedClaims(t, root, nodeOf(t, alice), claims), policy, ctx)
		return err
	}
	if err := authorize(map[string]any{"exp": now + MaxLifetime}); err != nil {
		t.Fatalf("an exp at MaxLifetime: %v", err)
	}
	for name, exp := range map[string]int64{
		"one second past MaxLifetime": now + MaxLifetime + 1,
		"an exp in milliseconds":      (now + 3600) * 1000,
	} {
		err := authorize(map[string]any{"exp": exp})
		if !errors.Is(err, ErrExpBeyondMaxLifetime) || RefusalName(err) != "exp_beyond_max_lifetime" {
			t.Errorf("%s: %v, want exp_beyond_max_lifetime", name, err)
			continue
		}
		for _, v := range []int64{exp, now} {
			if !strings.Contains(err.Error(), strconv.FormatInt(v, 10)) {
				t.Errorf("%s: %q does not name %d", name, err, v)
			}
		}
	}
	// Beside expired in the check order: before nbf.
	if err := authorize(map[string]any{"exp": (now + 3600) * 1000, "nbf": now + 60}); !errors.Is(err, ErrExpBeyondMaxLifetime) {
		t.Errorf("an exp in milliseconds with an nbf to come: %v, want exp_beyond_max_lifetime", err)
	}
}

// Create's refusal of an exp beyond MaxLifetime is the refusal Authorize
// gives, by macula's name.
func TestCreateRefusesAnExpBeyondMaxLifetimeByMaculasName(t *testing.T) {
	root := teststation.Key(t, profile.PQPure, "ucan lifetime name")
	_, err := Create(root, [32]byte{}, nil, Options{Exp: time.Now().UnixMilli()})
	if RefusalName(err) != "exp_beyond_max_lifetime" {
		t.Fatalf("%v, want exp_beyond_max_lifetime", err)
	}
}
