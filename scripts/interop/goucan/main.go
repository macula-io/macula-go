// Command goucan mints UCANs with macula-go's ucan package and writes them as
// JSON cases, each with the policy, context and verdict macula must reach, for
// scripts/interop/erlang_ucan.escript to authorize with macula_ucan: the
// reverse of the vectors, which macula mints and macula-go checks.
//
//	go run ./scripts/interop/goucan > go_ucans.json
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/ucan"
)

type testCase struct {
	Name      string   `json:"name"`
	Profile   string   `json:"profile"`
	Token     string   `json:"token"`
	Proofs    []string `json:"proofs"`
	Issuer    string   `json:"issuer"`
	Caller    string   `json:"caller"`
	Now       int64    `json:"now"`
	Realm     string   `json:"realm"`
	Procedure string   `json:"procedure"`
	Verdict   string   `json:"verdict"`
}

func main() {
	const now = int64(1790000000)
	realm := sha256.Sum256([]byte("io.macula"))
	var cases []testCase
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		key := func() *identity.NodeKey {
			k, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
			must(err)
			return k
		}
		node := func(k *identity.NodeKey) [32]byte { id, err := k.NodeID(); must(err); return id }
		root, alice, bob := key(), key(), key()
		mint := func(issuer, audience *identity.NodeKey, with string, o ucan.Options) string {
			token, err := ucan.Create(issuer, node(audience), []ucan.Capability{{With: with, Can: "invoke"}}, o)
			must(err)
			return string(token)
		}
		toAlice := mint(root, alice, "mri:org:io.macula/acme", ucan.Options{Exp: now + 3600})
		nbf := now - 60
		toBob := mint(alice, bob, "mri:proc:io.macula/acme/count_v1",
			ucan.Options{Exp: now + 60, Nbf: &nbf, Nnc: "n1", Prf: []string{ucan.ProofID([]byte(toAlice))}})
		add := func(name, token string, proofs []string, caller *identity.NodeKey, verdict string) {
			if proofs == nil {
				proofs = []string{}
			}
			r, c := node(root), node(caller)
			cases = append(cases, testCase{Name: name, Profile: string(p), Token: token, Proofs: proofs,
				Issuer: hex.EncodeToString(r[:]), Caller: hex.EncodeToString(c[:]), Now: now,
				Realm: hex.EncodeToString(realm[:]), Procedure: "acme/count_v1", Verdict: verdict})
		}
		add("root token", toAlice, nil, alice, "ok")
		add("delegated chain", toBob, []string{toAlice}, bob, "ok")
		add("presented by another node", toAlice, nil, bob, "not_the_audience")
		add("chain without its proof", toBob, nil, bob, "missing_proof")
		add("expired", mint(root, alice, "mri:realm:io.macula", ucan.Options{Exp: now}), nil, alice, "expired")
		// The furthest exp either side accepts: macula refuses one second more.
		add("exp at the max lifetime", mint(root, alice, "mri:realm:io.macula", ucan.Options{Exp: now + ucan.MaxLifetime}),
			nil, alice, "ok")
	}
	out, err := json.MarshalIndent(cases, "", "  ")
	must(err)
	fmt.Println(string(out))
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "goucan:", err)
		os.Exit(1)
	}
}
