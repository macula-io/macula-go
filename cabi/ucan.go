package main

// #include <stdint.h>
import "C"

import (
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ucan"
)

// UCANs (macula 12, D7): a node mints one for another node with
// macula_ucan_create, a caller presents one and its chain's proofs with
// macula_pool_call_with and macula_pool_open_stream_with, and a provider gates
// a procedure on one with macula_pool_serve_gated and
// macula_pool_serve_stream_gated.

// ucanOptions is options_json of macula_ucan_create.
type ucanOptions struct {
	Nbf *int64         `json:"nbf"`
	Nnc string         `json:"nnc"`
	Fct map[string]any `json:"fct"`
	Prf []string       `json:"prf"`
}

// ucanCreate is key's token for audience granting caps_json, a JSON array of
// {"with","can"}, until exp (Unix seconds), with options_json's optional
// claims (NULL or "" for none).
func ucanCreate(key *identity.NodeKey, audience [32]byte, capsJSON string, exp int64, optionsJSON string) (string, error) {
	var caps []ucan.Capability
	if err := decodeStrict("caps_json", capsJSON, &caps); err != nil {
		return "", err
	}
	var o ucanOptions
	if optionsJSON != "" {
		if err := decodeStrict("options_json", optionsJSON, &o); err != nil {
			return "", err
		}
	}
	token, err := ucan.Create(key, audience, caps, ucan.Options{Exp: exp, Nbf: o.Nbf, Nnc: o.Nnc, Fct: o.Fct, Prf: o.Prf})
	if err != nil {
		return "", invalidArgument("%v", err)
	}
	return string(token), nil
}

// credentials are the UCAN a call or an open presents and its chain's proofs.
type credentials struct {
	token  []byte
	proofs [][]byte
}

// credentialsOf is a token (NULL or "" for none) and proofs_json, a JSON array
// of the chain's tokens (NULL or "" for none).
func credentialsOf(token, proofsJSON string) (credentials, error) {
	c := credentials{}
	if token != "" {
		c.token = []byte(token)
	}
	if proofsJSON == "" {
		return c, nil
	}
	var proofs []string
	if err := decodeStrict("proofs_json", proofsJSON, &proofs); err != nil {
		return c, err
	}
	for _, p := range proofs {
		c.proofs = append(c.proofs, []byte(p))
	}
	return c, nil
}

// policyJSON is policy_json: {"kind":"ucan_required","issuer"} or
// {"kind":"realm_member_required","key_id","can"}, ids as hex.
type policyJSON struct {
	Kind   string `json:"kind"`
	Issuer string `json:"issuer"`
	KeyID  string `json:"key_id"`
	Can    string `json:"can"`
}

// policyOf is the policy policy_json names. A field another kind names is
// refused, as a misspelt one is.
func policyOf(text string) (ucan.Policy, error) {
	var p policyJSON
	if err := decodeStrict("policy_json", text, &p); err != nil {
		return nil, err
	}
	switch p.Kind {
	case "ucan_required":
		if p.KeyID != "" || p.Can != "" {
			return nil, invalidArgument("policy_json: ucan_required names an issuer only")
		}
		issuer, err := hexID("policy_json's issuer", p.Issuer)
		if err != nil {
			return nil, err
		}
		return ucan.UCANRequired{Issuer: issuer}, nil
	case "realm_member_required":
		if p.Issuer != "" {
			return nil, invalidArgument("policy_json: realm_member_required names a key_id and a can")
		}
		keyID, err := hexID("policy_json's key_id", p.KeyID)
		if err != nil {
			return nil, err
		}
		if p.Can == "" {
			return nil, invalidArgument("policy_json: realm_member_required needs a can")
		}
		return ucan.RealmMemberRequired{KeyID: keyID, Can: p.Can}, nil
	}
	return nil, invalidArgument("policy_json: kind is ucan_required or realm_member_required, not %q", p.Kind)
}

//export macula_ucan_create
func macula_ucan_create(h C.uintptr_t, audience32 *C.uint8_t, capsJSON *C.char, exp C.int64_t, optionsJSON *C.char,
	errOut **C.char) *C.char {
	key := keyOf(h, errOut)
	if key == nil {
		return nil
	}
	audience, ok := id32(audience32)
	if !ok {
		setErr(errOut, invalidArgument("the audience node_id is NULL"))
		return nil
	}
	token, err := ucanCreate(key, audience, goString(capsJSON), int64(exp), goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return nil
	}
	return cString(token)
}

//export macula_ucan_proof_id
func macula_ucan_proof_id(token *C.char, errOut **C.char) *C.char {
	text := goString(token)
	if text == "" {
		setErr(errOut, invalidArgument("the token is NULL or empty"))
		return nil
	}
	return cString(ucan.ProofID([]byte(text)))
}

// gatedPolicy is policy_json of a gated serve, which must name one:
// macula_pool_serve serves an open procedure.
func gatedPolicy(text string) (ucan.Policy, error) {
	if text == "" {
		return nil, invalidArgument("policy_json is required; serve an open procedure with macula_pool_serve")
	}
	return policyOf(text)
}
