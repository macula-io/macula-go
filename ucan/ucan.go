// Package ucan is macula 12's UCAN, macula's macula_ucan in Go: tokens signed
// in the node's crypto profile (D7), and a provider's authorization of one.
// macula's test/vectors/UCAN_V1.md is the contract, and testdata holds its
// vectors; every verdict here is macula's, reached in the same order.
//
// A token is a JWT, header.payload.signature, each part base64url without
// padding. The header names the profile's algorithm: ML-DSA-87 in pq_pure,
// ML-DSA-87-PS384 (the LAMPS composite id-MLDSA87-RSA4096-PSS-SHA512) in
// pq_hybrid. The signature is the issuer's node key's over the header and
// payload as sent. The payload's iss is a did:key for the issuer's key as
// carried; aud is the lowercase hex node_id of the node that presents the
// token, which must be the request's verified caller; cap lists {with, can};
// exp is in seconds.
//
// A token may rest on a parent: its prf names the parent by ProofID, and the
// parents travel beside it in the request's caller-signed proofs. The chain
// is walked to its root, which must be the issuer the policy names; each
// link's own signature and validity window hold, each parent's aud is the
// node_id of its child's issuer, can is equal at every step, and a child's
// capability is covered by one of its parent's (Covers). Every proof that
// travelled must be used.
package ucan

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
)

const (
	typ = "JWT"
	ucv = "0.10.0"
	// The did:key key types: mldsa-87-pub, and Macula's own, private-use, for
	// the composite (no multicodec yet).
	codecMLDSA87        = 0x1212
	codecMLDSA87RSA4096 = 0x300087
)

// Refusal is why a token does not authorize: one of macula_ucan's refusals,
// by the same name.
type Refusal struct{ name string }

func (r *Refusal) Error() string { return "ucan: " + r.name }

// Name is the refusal's name in macula: "not_the_audience", say.
func (r *Refusal) Name() string { return r.name }

var (
	ErrMalformed             = &Refusal{"malformed"}
	ErrWrongAlgorithm        = &Refusal{"wrong_algorithm"}
	ErrSignatureInvalid      = &Refusal{"signature_invalid"}
	ErrNotTheIssuer          = &Refusal{"not_the_issuer"}
	ErrNotTheAudience        = &Refusal{"not_the_audience"}
	ErrExpired               = &Refusal{"expired"}
	ErrNotYetValid           = &Refusal{"not_yet_valid"}
	ErrMissingCapability     = &Refusal{"missing_capability"}
	ErrMissingProof          = &Refusal{"missing_proof"}
	ErrUnreferencedProof     = &Refusal{"unreferenced_proof"}
	ErrNotTheDelegate        = &Refusal{"not_the_delegate"}
	ErrChainNotLinear        = &Refusal{"chain_not_linear"}
	ErrGrantsMoreThanProof   = &Refusal{"grants_more_than_proof"}
	ErrCanChanged            = &Refusal{"can_changed"}
	ErrWrongRealm            = &Refusal{"wrong_realm"}
	ErrRealmNameNotCanonical = &Refusal{"realm_name_not_canonical"}
	ErrProcedureWithoutOrg   = &Refusal{"procedure_without_org"}
)

// RefusalName is macula's name for err's refusal, or "" for an error that is
// not a refusal.
func RefusalName(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.name
	}
	return ""
}

// Policy is what a gated procedure requires of a request's token.
type Policy interface{ isPolicy() }

// UCANRequired is a token whose chain is rooted at the identity key of this
// node_id.
type UCANRequired struct{ Issuer [32]byte }

// RealmMemberRequired is a token whose chain is rooted at the realm key of
// this key id, granting a capability with this can.
type RealmMemberRequired struct {
	KeyID [32]byte
	Can   string
}

func (UCANRequired) isPolicy()        {}
func (RealmMemberRequired) isPolicy() {}

// Request is the request a token is presented with: its realm id and
// procedure.
type Request struct {
	Realm     [32]byte
	Procedure string
}

// Context is what a token is authorized against: the request's verified
// caller, the provider's profile, the time in seconds, the request (nil to
// check the token alone, as a gate with no request in front of it), and the
// proofs that travelled with it, keyed by ProofID.
type Context struct {
	Caller  [32]byte
	Profile profile.Profile
	Now     int64
	Request *Request
	Proofs  map[string][]byte
}

// Capability is one grant: a with (an MRI) and a can.
type Capability struct {
	With string `json:"with"`
	Can  string `json:"can"`
}

// Options are a token's claims beyond iss, aud and cap: Exp (seconds) is
// required, the rest optional.
type Options struct {
	Exp int64
	Nbf *int64
	Nnc string
	Fct map[string]any
	// Prf names the token's parent by ProofID; at most one.
	Prf []string
}

// Create is a token from issuer's identity key, for the audience's node_id,
// granting caps until o.Exp.
func Create(issuer *identity.NodeKey, audience [32]byte, caps []Capability, o Options) ([]byte, error) {
	if issuer.Purpose() != identity.PurposeIdentity {
		return nil, fmt.Errorf("ucan: a token is signed by an identity key, not a %s key", issuer.Purpose())
	}
	algorithm, err := alg(issuer.Profile())
	if err != nil {
		return nil, err
	}
	if caps == nil {
		caps = []Capability{}
	}
	claims := map[string]any{
		"iss": DIDKey(issuer.PublicKey(), issuer.Profile()),
		"aud": hex.EncodeToString(audience[:]),
		"cap": caps,
		"exp": o.Exp,
	}
	if o.Nbf != nil {
		claims["nbf"] = *o.Nbf
	}
	if o.Nnc != "" {
		claims["nnc"] = o.Nnc
	}
	if o.Fct != nil {
		claims["fct"] = o.Fct
	}
	if o.Prf != nil {
		claims["prf"] = o.Prf
	}
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "typ": typ, "ucv": ucv})
	payload, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("ucan: claims: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	signature, err := issuer.Sign([]byte(input))
	if err != nil {
		return nil, err
	}
	return []byte(input + "." + base64.RawURLEncoding.EncodeToString(signature)), nil
}

func alg(p profile.Profile) (string, error) {
	switch p {
	case profile.PQPure:
		return "ML-DSA-87", nil
	case profile.PQHybrid:
		return "ML-DSA-87-PS384", nil
	}
	return "", fmt.Errorf("ucan: no algorithm for profile %q", p)
}

// ProofID is the id a child's prf names a parent token by: the lowercase hex
// of the SHA-384 of the token's bytes as they travel.
func ProofID(token []byte) string {
	sum := sha512.Sum384(token)
	return hex.EncodeToString(sum[:])
}

// checked is a token parsed, and as far as it has been checked.
type checked struct {
	header    map[string]any
	claims    map[string]any
	signature []byte
	input     []byte
	issuerKey []byte
	// granted is the capabilities a step of the chain has to cover.
	granted []any
}

// Authorize is whether token authorizes ctx's caller under p: the token's
// claims when it does, or the first refusal, in macula_ucan's order.
func Authorize(token []byte, p Policy, ctx Context) (map[string]any, error) {
	c, err := parsed(token)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(*checked) error{
		func(c *checked) error { return algorithmIs(ctx.Profile, c) },
		func(c *checked) error { return signedByIss(ctx.Profile, c) },
		func(c *checked) error { return audienceIs(ctx.Caller, c) },
		func(c *checked) error { return validAt(ctx.Now, c) },
		func(c *checked) error { return grants(p, ctx, c) },
		func(c *checked) error { return chained(p, ctx, c) },
	} {
		if err := step(c); err != nil {
			return nil, err
		}
	}
	return c.claims, nil
}

// ---- the chain ----

func chained(p Policy, ctx Context, c *checked) error {
	proofs := make(map[string][]byte, len(ctx.Proofs))
	for id, proof := range ctx.Proofs {
		proofs[id] = proof
	}
	if err := walk(p, ctx, c, c.granted, proofs); err != nil {
		return err
	}
	if len(proofs) != 0 {
		return ErrUnreferencedProof
	}
	return nil
}

// walk checks c's link to its parent, up to the root, which must be the
// issuer p names; each proof it uses is taken out of proofs.
func walk(p Policy, ctx Context, c *checked, granted []any, proofs map[string][]byte) error {
	prf, present := c.claims["prf"]
	if !present {
		return issuedBy(p, c, ctx.Profile)
	}
	ids, ok := prf.([]any)
	switch {
	case !ok:
		return ErrMalformed
	case len(ids) == 0:
		return issuedBy(p, c, ctx.Profile)
	case len(ids) > 1:
		return ErrChainNotLinear
	}
	id, ok := ids[0].(string)
	if !ok {
		return ErrChainNotLinear
	}
	proof, ok := proofs[id]
	if !ok {
		return ErrMissingProof
	}
	delete(proofs, id)
	parent, err := chainLink(proof, ctx)
	if err != nil {
		return err
	}
	if err := delegatesTo(parent, c, ctx.Profile); err != nil {
		return err
	}
	if err := narrowsTo(parent, granted); err != nil {
		return err
	}
	return walk(p, ctx, parent, parent.granted, proofs)
}

// chainLink is a parent checked as a token: parts, algorithm, signature and
// validity window. Its audience and capability are checked against its child.
func chainLink(token []byte, ctx Context) (*checked, error) {
	c, err := parsed(token)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(*checked) error{
		func(c *checked) error { return algorithmIs(ctx.Profile, c) },
		func(c *checked) error { return signedByIss(ctx.Profile, c) },
		func(c *checked) error { return validAt(ctx.Now, c) },
	} {
		if err := step(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func delegatesTo(parent, child *checked, p profile.Profile) error {
	node := identity.NodeIDOf(child.issuerKey, p)
	if parent.claims["aud"] != hex.EncodeToString(node[:]) {
		return ErrNotTheDelegate
	}
	return nil
}

// narrowsTo is whether every capability the child hands on is one parent
// granted: the same can, and a with parent's covers. What parent granted is
// what the step above it has to cover.
func narrowsTo(parent *checked, children []any) error {
	caps, _ := parent.claims["cap"].([]any)
	var granted []any
	for _, child := range children {
		cap, err := covering(caps, child)
		if err != nil {
			return err
		}
		granted = append(granted, cap)
	}
	parent.granted = granted
	return nil
}

func covering(caps []any, child any) (any, error) {
	childCap, ok := child.(map[string]any)
	if !ok {
		return nil, ErrMalformed
	}
	childWith, hasWith := childCap["with"]
	childCan, hasCan := childCap["can"]
	if !hasWith || !hasCan {
		return nil, ErrMalformed
	}
	childWithText, _ := childWith.(string)
	for _, entry := range caps {
		cap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		with, isText := cap["with"].(string)
		can, hasCan := cap["can"]
		if _, hasWith := cap["with"]; !hasWith || !hasCan || !isText {
			continue
		}
		if jsonEqual(can, childCan) && isTextValue(childWith) && Covers(with, childWithText) {
			return cap, nil
		}
	}
	return nil, whyNotNarrowed(caps, childWith)
}

// whyNotNarrowed: a parent that granted the same authority under another can
// changed it; one of another realm is wrong_realm; otherwise it granted less
// than its child hands on. The first of its capabilities decides.
func whyNotNarrowed(caps []any, childWith any) error {
	if len(caps) == 0 {
		return ErrGrantsMoreThanProof
	}
	cap, ok := caps[0].(map[string]any)
	if !ok {
		return ErrGrantsMoreThanProof
	}
	with, isText := cap["with"].(string)
	if _, hasCan := cap["can"]; !hasCan || !isText {
		return ErrGrantsMoreThanProof
	}
	childWithText, childIsText := childWith.(string)
	switch {
	case !childIsText || !sameRealm(with, childWithText):
		return ErrWrongRealm
	case Covers(with, childWithText):
		return ErrCanChanged
	}
	return ErrGrantsMoreThanProof
}

func sameRealm(with, other string) bool {
	a, err := grant(with)
	if err != nil {
		return false
	}
	b, err := grant(other)
	if err != nil {
		return false
	}
	return a.realm == b.realm
}

// issuedBy checks the chain's root: its issuer is the one the policy names.
func issuedBy(p Policy, c *checked, prof profile.Profile) error {
	switch policy := p.(type) {
	case UCANRequired:
		if identity.NodeIDOf(c.issuerKey, prof) != policy.Issuer {
			return ErrNotTheIssuer
		}
	case RealmMemberRequired:
		if identity.KeyIDOf(c.issuerKey, prof) != policy.KeyID {
			return ErrNotTheIssuer
		}
	default:
		return ErrNotTheIssuer
	}
	return nil
}

// ---- one token ----

// parsed is a token's three parts: its header and claims decoded as JSON
// objects, and its signature, with the header and payload as received.
func parsed(token []byte) (*checked, error) {
	parts := bytes.Split(token, []byte("."))
	if len(parts) != 3 {
		return nil, ErrMalformed
	}
	header, ok := jsonObject(parts[0])
	if !ok {
		return nil, ErrMalformed
	}
	claims, ok := jsonObject(parts[1])
	if !ok {
		return nil, ErrMalformed
	}
	signature, err := base64.RawURLEncoding.DecodeString(string(parts[2]))
	if err != nil {
		return nil, ErrMalformed
	}
	input := make([]byte, 0, len(parts[0])+1+len(parts[1]))
	input = append(append(append(input, parts[0]...), '.'), parts[1]...)
	return &checked{header: header, claims: claims, signature: signature, input: input}, nil
}

func algorithmIs(p profile.Profile, c *checked) error {
	want, err := alg(p)
	if err != nil {
		return ErrWrongAlgorithm
	}
	algorithm, isText := c.header["alg"].(string)
	if isText && algorithm == want && c.header["typ"] == typ && c.header["ucv"] == ucv {
		return nil
	}
	if isText {
		return ErrWrongAlgorithm
	}
	return ErrMalformed
}

// signedByIss: every claim has its shape before anything is verified, and the
// signature is checked before any claim is acted on.
func signedByIss(p profile.Profile, c *checked) error {
	iss, issOK := c.claims["iss"].(string)
	_, audOK := c.claims["aud"].(string)
	_, capOK := c.claims["cap"].([]any)
	_, expOK := integer(c.claims["exp"])
	if !issOK || !audOK || !capOK || !expOK {
		return ErrMalformed
	}
	carried, err := CarriedKey(iss, p)
	if err != nil {
		return ErrMalformed
	}
	if !identity.Verify(c.input, c.signature, carried, p) {
		return ErrSignatureInvalid
	}
	c.issuerKey = carried
	return nil
}

func audienceIs(caller [32]byte, c *checked) error {
	if c.claims["aud"] != hex.EncodeToString(caller[:]) {
		return ErrNotTheAudience
	}
	return nil
}

func validAt(now int64, c *checked) error {
	exp, _ := integer(c.claims["exp"])
	if now >= exp {
		return ErrExpired
	}
	raw, present := c.claims["nbf"]
	if !present {
		return nil
	}
	nbf, ok := integer(raw)
	switch {
	case !ok:
		return ErrMalformed
	case now < nbf:
		return ErrNotYetValid
	}
	return nil
}

// ---- capabilities ----

// grants is the capability the request needs: one the token grants, whose can
// is the policy's where it names one, and whose with covers the request's
// realm and procedure. With no request, the can alone.
func grants(p Policy, ctx Context, c *checked) error {
	caps, _ := c.claims["cap"].([]any)
	if ctx.Request != nil {
		return requested(p, *ctx.Request, caps, c)
	}
	switch policy := p.(type) {
	case UCANRequired:
		c.granted = caps
		return nil
	case RealmMemberRequired:
		for _, entry := range caps {
			if cap, ok := entry.(map[string]any); ok {
				if can, present := cap["can"]; present && jsonEqual(can, policy.Can) {
					c.granted = []any{cap}
					return nil
				}
			}
		}
		return whyNotGranted(caps, nil)
	}
	return ErrMissingCapability
}

func requested(p Policy, r Request, caps []any, c *checked) error {
	if _, hasOrg, err := record.ProcedureOrg(r.Procedure); err != nil || !hasOrg {
		return ErrProcedureWithoutOrg
	}
	for _, entry := range caps {
		cap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		with, isText := cap["with"].(string)
		can, hasCan := cap["can"]
		if !isText || !hasCan || !canMatches(p, can) {
			continue
		}
		g, err := grant(with)
		if err != nil || sha256.Sum256([]byte(g.realm)) != r.Realm {
			continue
		}
		if Covers(with, "mri:proc:"+g.realm+"/"+r.Procedure) {
			c.granted = []any{cap}
			return nil
		}
	}
	return whyNotGranted(caps, &r.Realm)
}

func canMatches(p Policy, can any) bool {
	if policy, ok := p.(RealmMemberRequired); ok {
		return jsonEqual(can, policy.Can)
	}
	return true
}

// whyNotGranted is why no capability answered: the first text with decides
// (a grant not well formed, or one in another realm, says so), and otherwise
// the capability is missing. realm is nil when there is no request.
func whyNotGranted(caps []any, realm *[32]byte) error {
	for _, entry := range caps {
		cap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		with, isText := cap["with"].(string)
		if !isText {
			continue
		}
		g, err := grant(with)
		switch {
		case errors.Is(err, ErrMalformed):
			return ErrMissingCapability
		case err != nil:
			return err
		case realm == nil:
			return ErrMissingCapability
		case sha256.Sum256([]byte(g.realm)) == *realm:
			return ErrMissingCapability
		}
		return ErrWrongRealm
	}
	return ErrMissingCapability
}

// grantOf is a with parsed: a realm, an org of that realm, or one procedure
// of that realm.
type grantOf struct {
	kind                  string
	realm, org, procedure string
}

// grant is a with parsed into its grant, or why it is not one.
func grant(with string) (grantOf, error) {
	switch {
	case strings.HasPrefix(with, "mri:realm:"):
		realm := strings.TrimPrefix(with, "mri:realm:")
		if !canonicalRealmName(realm) {
			return grantOf{}, ErrRealmNameNotCanonical
		}
		return grantOf{kind: "realm", realm: realm}, nil
	case strings.HasPrefix(with, "mri:org:"):
		realm, org, found := strings.Cut(strings.TrimPrefix(with, "mri:org:"), "/")
		if !found || org == "" {
			return grantOf{}, ErrMalformed
		}
		if !canonicalRealmName(realm) {
			return grantOf{}, ErrRealmNameNotCanonical
		}
		return grantOf{kind: "org", realm: realm, org: org}, nil
	case strings.HasPrefix(with, "mri:proc:"):
		realm, procedure, found := strings.Cut(strings.TrimPrefix(with, "mri:proc:"), "/")
		if !found {
			return grantOf{}, ErrMalformed
		}
		if !canonicalRealmName(realm) {
			return grantOf{}, ErrRealmNameNotCanonical
		}
		if _, hasOrg, err := record.ProcedureOrg(procedure); err != nil || !hasOrg {
			return grantOf{}, ErrProcedureWithoutOrg
		}
		return grantOf{kind: "proc", realm: realm, procedure: procedure}, nil
	}
	return grantOf{}, ErrMalformed
}

// Covers is whether a grant covers another grant or a request, by D7's
// narrowing: a realm grant covers its realm, an org grant covers that org and
// its procedures, a procedure grant only itself. False for a with that is not
// one of the three MRIs, whose realm name is not canonical, or whose
// procedure has no org.
func Covers(parent, child string) bool {
	p, err := grant(parent)
	if err != nil {
		return false
	}
	c, err := grant(child)
	if err != nil {
		return false
	}
	switch p.kind {
	case "realm":
		return p.realm == c.realm
	case "org":
		if c.realm != p.realm {
			return false
		}
		if c.kind == "org" {
			return c.org == p.org
		}
		if c.kind == "proc" {
			org, hasOrg, _ := record.ProcedureOrg(c.procedure)
			return hasOrg && org == p.org
		}
		return false
	case "proc":
		return c.kind == "proc" && c.realm == p.realm && c.procedure == p.procedure
	}
	return false
}

// canonicalRealmName: at least one segment, segments joined by single dots,
// each of a-z, 0-9, hyphen or underscore. Case is never folded.
func canonicalRealmName(name string) bool {
	if name == "" {
		return false
	}
	for _, segment := range strings.Split(name, ".") {
		if segment == "" {
			return false
		}
		for _, r := range segment {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// ---- did:key ----

// DIDKey is the did:key for a key as carried in profile p.
func DIDKey(carried []byte, p profile.Profile) string {
	return "did:key:z" + base58btcEncode(append(varint(codec(p)), carried...))
}

// CarriedKey is the key a did:key carries, when it is a key in its one
// carried form for p (D13).
func CarriedKey(did string, p profile.Profile) ([]byte, error) {
	encoded, ok := strings.CutPrefix(did, "did:key:z")
	if !ok {
		return nil, ErrMalformed
	}
	prefix := varint(codec(p))
	decoded := base58btcDecode(encoded)
	if len(decoded) <= len(prefix) || !bytes.Equal(decoded[:len(prefix)], prefix) {
		return nil, ErrMalformed
	}
	carried := decoded[len(prefix):]
	if !identity.CarriedKeyWellFormed(carried, p) {
		return nil, ErrMalformed
	}
	return carried, nil
}

func codec(p profile.Profile) uint64 {
	if p == profile.PQHybrid {
		return codecMLDSA87RSA4096
	}
	return codecMLDSA87
}

// varint is an unsigned LEB128 varint, as multicodec prefixes are written.
func varint(n uint64) []byte {
	var out []byte
	for n >= 0x80 {
		out = append(out, byte(n&0x7f)|0x80)
		n >>= 7
	}
	return append(out, byte(n))
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58btcEncode is base58 with the Bitcoin alphabet, as multibase's
// base58btc: each leading zero byte is a leading 1.
func base58btcEncode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	digits := []byte{}
	for _, v := range b[zeros:] {
		carry := int(v)
		for i := range digits {
			carry += int(digits[i]) << 8
			digits[i] = byte(carry % 58)
			carry /= 58
		}
		for carry > 0 {
			digits = append(digits, byte(carry%58))
			carry /= 58
		}
	}
	out := make([]byte, 0, zeros+len(digits))
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i := len(digits) - 1; i >= 0; i-- {
		out = append(out, base58Alphabet[digits[i]])
	}
	return string(out)
}

// base58btcDecode is the bytes a base58btc text encodes, or nil for a text
// with a character outside the alphabet.
func base58btcDecode(text string) []byte {
	ones := 0
	for ones < len(text) && text[ones] == '1' {
		ones++
	}
	value := []byte{}
	for _, r := range text[ones:] {
		digit := strings.IndexRune(base58Alphabet, r)
		if digit < 0 {
			return nil
		}
		carry := digit
		for i := range value {
			carry += int(value[i]) * 58
			value[i] = byte(carry & 0xff)
			carry >>= 8
		}
		for carry > 0 {
			value = append(value, byte(carry&0xff))
			carry >>= 8
		}
	}
	out := make([]byte, ones, ones+len(value))
	for i := len(value) - 1; i >= 0; i-- {
		out = append(out, value[i])
	}
	return out
}

// ---- JSON ----

// jsonObject is a base64url segment decoded as one JSON object, its numbers
// kept as written.
func jsonObject(segment []byte) (map[string]any, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(string(segment))
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var object map[string]any
	if err := decoder.Decode(&object); err != nil || object == nil {
		return nil, false
	}
	if decoder.More() {
		return nil, false
	}
	return object, true
}

// integer is a JSON number written as an integer, as Erlang's json decodes
// one: a number with a fraction or an exponent is a float, never an integer.
// One beyond int64 is held at its bound, which compares the same against any
// time.
func integer(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok || strings.ContainsAny(n.String(), ".eE") {
		return 0, false
	}
	i, err := strconv.ParseInt(n.String(), 10, 64)
	if err == nil {
		return i, true
	}
	if strings.HasPrefix(n.String(), "-") {
		return math.MinInt64, true
	}
	return math.MaxInt64, true
}

func isTextValue(v any) bool {
	_, ok := v.(string)
	return ok
}

// jsonEqual is Erlang's =:= over decoded JSON: the same type and value.
func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
