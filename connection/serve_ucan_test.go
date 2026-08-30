package connection

import (
	"testing"

	"github.com/macula-io/macula-go-sdk/bolt4"
	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/ucan"
)

// These exercise buildCallReply directly (no network) to prove the
// UCAN policy gate added in ServeOneCallGated actually runs BEFORE
// lookup/dispatch, matching macula_station_link.erl's
// handle_inbound_call/2: an unauthorized call never reaches the
// handler at all, and a handler never sees the raw token.

func mustID(t *testing.T) identity.KeyPair {
	t.Helper()
	id, err := identity.Generate()
	if err != nil {
		t.Fatalf("identity.Generate: %v", err)
	}
	return id
}

func responseCode(t *testing.T, v cbor.Value) (isError bool, code uint8) {
	t.Helper()
	resp, err := frame.ParseCallResponse(v)
	if err != nil {
		t.Fatalf("ParseCallResponse: %v", err)
	}
	return resp.IsError, resp.Code
}

func TestBuildCallReplyOpenPolicyInvokesHandlerWithoutToken(t *testing.T) {
	selfID := mustID(t)
	invoked := false
	lookup := func(_ []byte, _ string) (CallHandler, bool) {
		return func(payload cbor.Value) (cbor.Value, error) {
			invoked = true
			return payload, nil
		}, true
	}
	callInfo := frame.CallInfo{
		CallID: make([]byte, 16), Procedure: "open.proc", Realm: make([]byte, 32),
		Payload: cbor.Text("hi"), Caller: selfID.NodeID(),
		// UcanToken deliberately absent.
	}
	reply := buildCallReply(callInfo, lookup, openPolicy, selfID.NodeID())
	isErr, _ := responseCode(t, reply)
	if isErr {
		t.Fatalf("open policy with no token should reach the handler, got an error frame")
	}
	if !invoked {
		t.Fatalf("handler was never invoked")
	}
}

func TestBuildCallReplyGatedPolicyRejectsMissingTokenWithoutInvokingHandler(t *testing.T) {
	selfID := mustID(t)
	requiredIssuer := mustID(t)
	invoked := false
	lookup := func(_ []byte, _ string) (CallHandler, bool) {
		return func(payload cbor.Value) (cbor.Value, error) {
			invoked = true
			return payload, nil
		}, true
	}
	policy := func(_ []byte, _ string) ucan.Policy { return ucan.Required(requiredIssuer.NodeID()) }
	callInfo := frame.CallInfo{
		CallID: make([]byte, 16), Procedure: "gated.proc", Realm: make([]byte, 32),
		Payload: cbor.Text("hi"), Caller: selfID.NodeID(),
		// UcanToken deliberately absent -- must be refused before lookup.
	}
	reply := buildCallReply(callInfo, lookup, policy, selfID.NodeID())
	isErr, code := responseCode(t, reply)
	if !isErr || bolt4.Code(code) != bolt4.Unauthorized {
		t.Fatalf("gated policy with no token: isError=%v code=%d, want ERROR Unauthorized(0x%02x)", isErr, code, bolt4.Unauthorized)
	}
	if invoked {
		t.Fatalf("handler was invoked despite a rejected/missing UCAN token -- gating must happen BEFORE dispatch")
	}
}

func TestBuildCallReplyGatedPolicyRejectsInvalidTokenWithoutInvokingHandler(t *testing.T) {
	selfID := mustID(t)
	requiredIssuer := mustID(t)
	wrongSigner := mustID(t)
	invoked := false
	lookup := func(_ []byte, _ string) (CallHandler, bool) {
		return func(payload cbor.Value) (cbor.Value, error) {
			invoked = true
			return payload, nil
		}, true
	}
	badToken, err := ucan.Create("iss", "aud", nil, wrongSigner, ucan.CreateOpts{})
	if err != nil {
		t.Fatalf("ucan.Create: %v", err)
	}
	policy := func(_ []byte, _ string) ucan.Policy { return ucan.Required(requiredIssuer.NodeID()) }
	callInfo := frame.CallInfo{
		CallID: make([]byte, 16), Procedure: "gated.proc", Realm: make([]byte, 32),
		Payload: cbor.Text("hi"), Caller: selfID.NodeID(), UcanToken: badToken,
	}
	reply := buildCallReply(callInfo, lookup, policy, selfID.NodeID())
	isErr, code := responseCode(t, reply)
	if !isErr || bolt4.Code(code) != bolt4.Unauthorized {
		t.Fatalf("gated policy with a token from the wrong signer: isError=%v code=%d, want ERROR Unauthorized(0x%02x)", isErr, code, bolt4.Unauthorized)
	}
	if invoked {
		t.Fatalf("handler was invoked despite an invalid UCAN token -- gating must happen BEFORE dispatch")
	}
}

func TestBuildCallReplyGatedPolicyAcceptsValidTokenAndInvokesHandler(t *testing.T) {
	selfID := mustID(t)
	requiredIssuer := mustID(t)
	invoked := false
	var handlerSawToken bool
	lookup := func(_ []byte, _ string) (CallHandler, bool) {
		return func(payload cbor.Value) (cbor.Value, error) {
			invoked = true
			// CallHandler's signature is payload-only -- there is no way
			// for it to see the raw token even if it wanted to. This is
			// asserted structurally (the type signature itself), not by
			// a runtime check here; handlerSawToken stays false by
			// construction.
			return payload, nil
		}, true
	}
	goodToken, err := ucan.Create("iss", "aud", []ucan.Capability{{With: "x", Can: "y"}}, requiredIssuer, ucan.CreateOpts{})
	if err != nil {
		t.Fatalf("ucan.Create: %v", err)
	}
	policy := func(_ []byte, _ string) ucan.Policy { return ucan.Required(requiredIssuer.NodeID()) }
	callInfo := frame.CallInfo{
		CallID: make([]byte, 16), Procedure: "gated.proc", Realm: make([]byte, 32),
		Payload: cbor.Text("authorized payload"), Caller: selfID.NodeID(), UcanToken: goodToken,
	}
	reply := buildCallReply(callInfo, lookup, policy, selfID.NodeID())
	isErr, _ := responseCode(t, reply)
	if isErr {
		t.Fatalf("gated policy with a valid token should reach the handler, got an error frame")
	}
	if !invoked {
		t.Fatalf("handler was never invoked despite a valid UCAN token")
	}
	if handlerSawToken {
		t.Fatalf("impossible per CallHandler's signature -- sanity check only")
	}
}

func TestServeOneCallStillOpenByDefault(t *testing.T) {
	// ServeOneCall must behave identically to ServeOneCallGated with an
	// always-open policy -- confirmed structurally: ServeOneCall's own
	// body is a one-line delegation to ServeOneCallGated(lookup,
	// openPolicy, id, timeout). This test just pins openPolicy's own
	// behavior so a future edit can't quietly make it gated.
	if p := openPolicy(nil, ""); p.Gated {
		t.Fatalf("openPolicy returned a gated policy: %+v", p)
	}
}
