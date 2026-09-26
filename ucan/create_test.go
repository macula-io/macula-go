package ucan

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

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
