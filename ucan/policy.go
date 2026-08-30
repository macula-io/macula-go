package ucan

// Policy describes what a service requires to answer one (realm,
// procedure): open (any identified caller, the default) or UCAN-gated
// (the caller's token must verify against RequiredIssuer). Mirrors
// macula_station_link.erl's own policy shape exactly — `open |
// {ucan_required, Issuer}` — where "Issuer" there is the 32-byte Ed25519
// public key the gate checks the token's signature against, not a DID
// string (the reference code passes it straight to macula_ucan_nif:verify/2,
// whose second argument is a raw public key).
//
// Gating happens BEFORE a handler runs — see connection.ServeOneCallGated
// — so a rejected caller never reaches business logic, and an accepted
// caller's handler never sees the raw token either; the policy layer
// already did the only thing that mattered with it.
type Policy struct {
	Gated          bool
	RequiredIssuer []byte // 32-byte Ed25519 public key; meaningful only if Gated
}

// Open is the default, ungated policy: any identified caller may invoke
// the procedure, no UCAN token needed. Equivalent to Erlang's `open`.
var Open = Policy{}

// Required builds a UCAN-gated policy: a caller must present a token
// that verifies (signature, exp, nbf) against issuerPublicKey.
// Equivalent to Erlang's `{ucan_required, issuerPublicKey}`.
func Required(issuerPublicKey []byte) Policy {
	return Policy{Gated: true, RequiredIssuer: issuerPublicKey}
}

// Check applies p to an inbound CALL's ucanToken, returning nil if the
// call is authorized to proceed to lookup/dispatch. An open policy
// always passes; a gated policy requires ucanToken to Verify against
// RequiredIssuer.
func (p Policy) Check(ucanToken []byte) error {
	if !p.Gated {
		return nil
	}
	if len(ucanToken) == 0 {
		return ErrNoToken
	}
	_, err := Verify(ucanToken, p.RequiredIssuer)
	return err
}
