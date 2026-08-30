// Package ucan implements Macula's UCAN (User Controlled Authorization
// Networks) tokens: creation, verification, and introspection. Ported from
// macula_ucan_nif.erl — a JWT-shaped token (header.payload.signature,
// base64url-no-pad, dot-joined), EdDSA over Ed25519, UCAN spec version
// "0.10.0" (the older JWT-based draft; NOT the current non-JWT/IPLD UCAN
// 1.0 spec — confirmed by reading both the Erlang fallback and its Rust
// NIF (native/macula_ucan_nif/src/lib.rs) directly, both hand-roll this
// exact format rather than depending on a UCAN library, because no
// existing library implements 0.10.0 — the only actively maintained Go
// UCAN library (github.com/ucan-wg/go-ucan) targets UCAN 1.0.0-rc.1, an
// incompatible wire format (CBOR/IPLD envelope, not JWT). This package
// does the same: hand-rolled on stdlib crypto/ed25519 + encoding/json +
// encoding/base64, matching the reference exactly rather than adopting an
// incompatible library.
//
// A token minted here verifies against macula-rust-sdk, the Erlang
// macula SDK, or vice versa — same header shape, same payload field
// names (iss/aud/exp/nbf/nnc/cap/fct/prf), same signing input
// (header_b64 + "." + payload_b64), same signature algorithm. Field
// ORDER in the JSON is not part of the compatibility contract (a
// verifier decodes into a struct, it never re-encodes and compares
// bytes), only the field NAMES and the exact bytes signed matter.
package ucan

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/macula-io/macula-go/identity"
)

const (
	alg = "EdDSA"
	typ = "JWT"
	ucv = "0.10.0"
)

var (
	// ErrInvalidToken means the token isn't a well-formed
	// header.payload.signature triple, or its payload isn't valid JSON —
	// mirrors macula_ucan_nif's {error, invalid_token}.
	ErrInvalidToken = errors.New("ucan: invalid token")
	// ErrInvalidSignature means the token parsed fine but its signature
	// does not verify against the given public key — mirrors
	// {error, invalid_signature}.
	ErrInvalidSignature = errors.New("ucan: invalid signature")
	// ErrInvalidPublicKey means the supplied public key isn't a 32-byte
	// Ed25519 key — mirrors {error, invalid_public_key}.
	ErrInvalidPublicKey = errors.New("ucan: invalid public key")
	// ErrExpired means the token's exp claim is in the past — mirrors
	// {error, expired}.
	ErrExpired = errors.New("ucan: token expired")
	// ErrNotYetValid means the token's nbf claim is in the future —
	// mirrors {error, not_yet_valid}.
	ErrNotYetValid = errors.New("ucan: token not yet valid")
	// ErrNoToken means a UCAN-gated procedure was called with no token at
	// all — mirrors macula_station_link.erl's check_ucan(<<>>, _) ->
	// unauthorized clause (an empty/absent token is refused before ever
	// attempting to verify anything).
	ErrNoToken = errors.New("ucan: no token presented for a gated procedure")
)

// Capability is one entry in a UCAN token's capability list — mirrors
// macula_ucan_nif's capability() :: #{with := binary(), can := binary()}.
type Capability struct {
	With string `json:"with"`
	Can  string `json:"can"`
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Ucv string `json:"ucv"`
}

// wirePayload is the JSON shape actually signed/transmitted. Field names
// match the reference exactly; Nonce is a pointer so an absent nnc is
// omitted rather than serialized as "".
type wirePayload struct {
	Issuer       string                 `json:"iss"`
	Audience     string                 `json:"aud"`
	ExpiresAt    *int64                 `json:"exp,omitempty"`
	NotBefore    *int64                 `json:"nbf,omitempty"`
	Nonce        *string                `json:"nnc,omitempty"`
	Capabilities []Capability           `json:"cap"`
	Facts        map[string]interface{} `json:"fct,omitempty"`
	Proofs       []string               `json:"prf"`
}

// Payload is a UCAN token's decoded claims — the Go-idiomatic
// counterpart to wirePayload, returned from Decode/Verify.
type Payload struct {
	Issuer       string
	Audience     string
	Capabilities []Capability
	ExpiresAt    *int64 // unix seconds, nil if absent
	NotBefore    *int64 // unix seconds, nil if absent
	Nonce        string // "" if absent
	Facts        map[string]interface{}
	Proofs       []string // CIDs of parent tokens
}

// CreateOpts are optional UCAN claims — mirrors macula_ucan_nif's
// ucan_opts() map.
type CreateOpts struct {
	ExpiresAt *int64
	NotBefore *int64
	Nonce     string
	Facts     map[string]interface{}
	Proofs    []string
}

// Create mints a new UCAN token, self-issued and signed by id. issuer and
// audience are opaque DID strings (e.g. "did:macula:io.macula.acme") —
// this package does not validate or resolve DID structure, matching
// macula_ucan_nif:create/4,5's own scope exactly (that's
// macula_did_nif's job on the Erlang side, out of scope here). id signs
// with its own Ed25519 private key; the resulting token verifies against
// id's public key (NodeID), same convention every advertised capability
// in this SDK already uses.
func Create(issuer, audience string, capabilities []Capability, id identity.KeyPair, opts CreateOpts) ([]byte, error) {
	if capabilities == nil {
		capabilities = []Capability{}
	}
	proofs := opts.Proofs
	if proofs == nil {
		proofs = []string{}
	}
	p := wirePayload{
		Issuer: issuer, Audience: audience,
		ExpiresAt: opts.ExpiresAt, NotBefore: opts.NotBefore,
		Capabilities: capabilities, Facts: opts.Facts, Proofs: proofs,
	}
	if opts.Nonce != "" {
		nonce := opts.Nonce
		p.Nonce = &nonce
	}

	headerJSON, err := json.Marshal(header{Alg: alg, Typ: typ, Ucv: ucv})
	if err != nil {
		return nil, fmt.Errorf("ucan: marshal header: %w", err)
	}
	payloadJSON, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("ucan: marshal payload: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerB64 + "." + payloadB64
	sig := id.Sign([]byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return []byte(signingInput + "." + sigB64), nil
}

func splitToken(token []byte) (headerB64, payloadB64, sigB64 string, err error) {
	parts := strings.Split(string(token), ".")
	if len(parts) != 3 {
		return "", "", "", ErrInvalidToken
	}
	return parts[0], parts[1], parts[2], nil
}

func decodePayload(payloadB64 string) (Payload, error) {
	raw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return Payload{}, ErrInvalidToken
	}
	var wp wirePayload
	if err := json.Unmarshal(raw, &wp); err != nil {
		return Payload{}, ErrInvalidToken
	}
	nonce := ""
	if wp.Nonce != nil {
		nonce = *wp.Nonce
	}
	return Payload{
		Issuer: wp.Issuer, Audience: wp.Audience, Capabilities: wp.Capabilities,
		ExpiresAt: wp.ExpiresAt, NotBefore: wp.NotBefore, Nonce: nonce,
		Facts: wp.Facts, Proofs: wp.Proofs,
	}, nil
}

// Decode parses a UCAN token's payload WITHOUT verifying its signature or
// checking expiration. Mirrors macula_ucan_nif:decode/1 — same warning
// applies: never use this for an authorization decision, only Verify
// does that.
func Decode(token []byte) (Payload, error) {
	_, payloadB64, _, err := splitToken(token)
	if err != nil {
		return Payload{}, err
	}
	return decodePayload(payloadB64)
}

// Verify checks a UCAN token's signature against publicKey (the
// claimed issuer's 32-byte Ed25519 public key) and its exp/nbf claims
// against the current time, returning the decoded payload only on full
// success. Mirrors macula_ucan_nif:verify/2 exactly, including its
// check ORDER (public key shape, then token shape, then exp, then nbf,
// then signature — matching both the Erlang fallback and the Rust NIF,
// which check claims before the signature; this package preserves that
// order for parity even though it means an invalid-but-well-formed
// token's expiry is observable before its signature is checked).
func Verify(token []byte, publicKey []byte) (Payload, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return Payload{}, ErrInvalidPublicKey
	}
	headerB64, payloadB64, sigB64, err := splitToken(token)
	if err != nil {
		return Payload{}, err
	}
	payload, err := decodePayload(payloadB64)
	if err != nil {
		return Payload{}, err
	}
	now := time.Now().Unix()
	if payload.ExpiresAt != nil && now > *payload.ExpiresAt {
		return Payload{}, ErrExpired
	}
	if payload.NotBefore != nil && now < *payload.NotBefore {
		return Payload{}, ErrNotYetValid
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return Payload{}, ErrInvalidToken
	}
	signingInput := headerB64 + "." + payloadB64
	if !identity.Verify(publicKey, []byte(signingInput), sig) {
		return Payload{}, ErrInvalidSignature
	}
	return payload, nil
}

// ComputeCID returns a UCAN token's content identifier: SHA-256 of the
// raw token bytes, base64url-no-pad encoded. NOT a real multihash/CIDv1
// — matches macula_ucan_nif:compute_cid/1's own (loosely-named) scheme
// exactly. Used only for proof-chain references between UCANs (a child
// token's prf entries name parent tokens by this value).
func ComputeCID(token []byte) string {
	sum := sha256.Sum256(token)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GetIssuer decodes token (without verifying it) and returns its iss
// claim. Mirrors macula_ucan_nif:get_issuer/1.
func GetIssuer(token []byte) (string, error) {
	p, err := Decode(token)
	if err != nil {
		return "", err
	}
	return p.Issuer, nil
}

// GetAudience decodes token (without verifying it) and returns its aud
// claim. Mirrors macula_ucan_nif:get_audience/1.
func GetAudience(token []byte) (string, error) {
	p, err := Decode(token)
	if err != nil {
		return "", err
	}
	return p.Audience, nil
}

// GetCapabilities decodes token (without verifying it) and returns its
// cap claim. Mirrors macula_ucan_nif:get_capabilities/1.
func GetCapabilities(token []byte) ([]Capability, error) {
	p, err := Decode(token)
	if err != nil {
		return nil, err
	}
	return p.Capabilities, nil
}

// GetExpiration decodes token (without verifying it) and returns its exp
// claim, or nil if absent. Mirrors macula_ucan_nif:get_expiration/1.
func GetExpiration(token []byte) (*int64, error) {
	p, err := Decode(token)
	if err != nil {
		return nil, err
	}
	return p.ExpiresAt, nil
}

// GetProofs decodes token (without verifying it) and returns its prf
// claim. Mirrors macula_ucan_nif:get_proofs/1.
func GetProofs(token []byte) ([]string, error) {
	p, err := Decode(token)
	if err != nil {
		return nil, err
	}
	return p.Proofs, nil
}

// IsExpired decodes token (without verifying it) and reports whether its
// exp claim is in the past. A token with no exp claim is never expired.
// Mirrors macula_ucan_nif:is_expired/1.
func IsExpired(token []byte) (bool, error) {
	p, err := Decode(token)
	if err != nil {
		return false, err
	}
	if p.ExpiresAt == nil {
		return false, nil
	}
	return time.Now().Unix() > *p.ExpiresAt, nil
}
