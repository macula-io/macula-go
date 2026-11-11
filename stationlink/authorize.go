package stationlink

import (
	"errors"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/ucan"
)

// The codes a gated procedure refuses a CALL or a STREAM_OPEN with, as
// macula's link's authorize_policy answers.
const (
	codeUnauthorized   = "unauthorized"
	codeMalformedFrame = "malformed_frame"
)

// validPolicy is a policy Serve accepts, one shape at a time as macula's
// advertise checks it: a ucan.Open, a ucan.UCANRequired, or a
// ucan.RealmMemberRequired that names a can. No policy is not one of the
// shapes: an offer that names none is refused (macula-go#57, #60).
func validPolicy(p ucan.Policy) bool {
	switch policy := p.(type) {
	case ucan.Open, ucan.UCANRequired:
		return true
	case ucan.RealmMemberRequired:
		return policy.Can != ""
	}
	return false
}

// authorize judges a verified request against its procedure's policy as
// macula's link does, returning the code to refuse it with, or "" to serve it.
// An open procedure serves any caller and reads no token. A gated one serves a
// request whose token ucan.Authorize accepts for the request's verified caller,
// now, and the request's realm and procedure, its proofs keyed by proof id; a
// proof no token in the chain names is what the caller sent being wrong, not
// the authority it claims, so malformed_frame, and every other refusal is
// unauthorized. A procedure with no policy serves nobody: the property this
// guard rests on is held here, whatever built the offer.
func (l *Link) authorize(policy ucan.Policy, request frame.VerifiedRequest) string {
	if policy == nil {
		return codeUnauthorized
	}
	proofs := make(map[string][]byte, len(request.Proofs))
	for _, proof := range request.Proofs {
		proofs[ucan.ProofID(proof)] = proof
	}
	_, err := ucan.Authorize(request.Token, policy, ucan.Context{Caller: request.Caller, Profile: l.profile,
		Now: time.Now().Unix(), Request: &ucan.Request{Realm: request.Realm, Procedure: request.Procedure}, Proofs: proofs})
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ucan.ErrUnreferencedProof):
		return codeMalformedFrame
	}
	return codeUnauthorized
}
