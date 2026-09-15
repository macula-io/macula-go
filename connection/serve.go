package connection

import (
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ucan"
)

// CallHandler answers one inbound CALL. Returning (payload, nil) sends
// a RESULT; returning (_, err) sends an ERROR (BOLT#4 UnknownError,
// detail=err.Error()); a panic inside the handler is recovered and
// sent as ERROR TemporaryRelayFailure — matching
// macula_station_link.erl's own safe_invoke_handler mapping exactly
// (including sending no detail on a crash, since the reference doesn't
// either — it only logs locally).
//
// A map payload reaches the handler with the caller's 32-byte node id,
// as bytes, under the text key "caller": the identity whose signature on
// the CALL verified, replacing any "caller" the sender wrote, as
// macula_station_link:with_caller/2 does. A payload that is not a map
// reaches the handler as it was sent and carries no caller.
type CallHandler func(payload cbor.Value) (cbor.Value, error)

// CallLookup resolves an inbound CALL's (realm, procedure) to a
// handler — e.g. a closure over a caller-owned map. A miss sends
// BOLT#4 UnknownNextPeer, matching the race
// macula_station_link.erl's own doc describes (an UNADVERTISE in
// flight vs. a stale forwarded CALL) — not expected in steady state,
// since the station only ever forwards a CALL for a procedure this
// connection actually advertised.
type CallLookup func(realm []byte, procedure string) (CallHandler, bool)

// PolicyLookup resolves an inbound CALL's (realm, procedure) to the
// ucan.Policy gating it, consulted BEFORE lookup — see
// ServeOneCallGated. Defaults to ucan.Open for any (realm, procedure) an
// implementation doesn't explicitly gate, matching Erlang's own
// open-by-default (stored as absence to keep its policy map small).
type PolicyLookup func(realm []byte, procedure string) ucan.Policy

func openPolicy(_ []byte, _ string) ucan.Policy { return ucan.Open }

// ErrServeOneCallTimeout is returned by ServeOneCall when timeout
// elapses with no inbound CALL frame arriving.
var ErrServeOneCallTimeout = errors.New("connection: serve_one_call: timed out waiting for an inbound CALL")

// ServeOneCall is the provider role's counterpart to Call: block for
// the next inbound CALL frame on the control stream, bounded by
// timeout, look it up via lookup, invoke the matching handler, and
// send the resulting RESULT or ERROR back over this same connection —
// see plans/PLAN_WIRE_PROTOCOL.md §6.9's routing description and
// macula_station_link.erl's handle_inbound_call/2, which this mirrors
// field for field, including its BOLT#4 error-code mapping.
//
// Any non-CALL frame that arrives first (e.g. a stray EVENT from an
// active Subscribe, or a RESULT/ERROR for some other in-flight Call)
// is discarded, not queued — the same "control stream, one thing at a
// time" limitation Call's own doc already carries. A session that
// needs to serve CALLs and also act as a caller/subscriber
// concurrently should use a second Session, exactly like this
// package's sibling stream package's own live provider/caller test
// does.
//
// A caller wanting a long-lived server loops on this:
//
//	for {
//	    if err := session.ServeOneCall(lookup, id, 30*time.Second); err != nil {
//	        // ErrServeOneCallTimeout just means nothing arrived -- keep looping.
//	    }
//	}
func (s *Session) ServeOneCall(lookup CallLookup, id identity.KeyPair, timeout time.Duration) error {
	return s.ServeOneCallGated(lookup, openPolicy, id, timeout)
}

// ServeOneCallGated is ServeOneCall, additionally gating each inbound
// CALL through policy BEFORE lookup runs — mirrors
// macula_station_link.erl's on_inbound_call/3 and handle_inbound_call/2: a
// CALL whose signature doesn't verify against its caller is ignored with no
// reply, and of the rest, an open
// policy (the default, ucan.Open) behaves identically to plain
// ServeOneCall; a ucan.Required policy demands a CALL's UcanToken verify
// against the required issuer, and refuses with BOLT#4 Unauthorized
// (0x10) WITHOUT ever invoking lookup or a handler if it doesn't — a
// CallHandler never sees the raw token either way, matching the
// reference's own handler contract (payload only).
func (s *Session) ServeOneCallGated(lookup CallLookup, policy PolicyLookup, id identity.KeyPair, timeout time.Duration) error {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case callInfo := <-s.rt.calls:
		reply := buildCallReply(s, callInfo, lookup, policy, id)
		err := s.send(frame.Sign(reply, id), time.Now().Add(s.sendTimeoutOrDefault()), nil)
		if code, refused := refusalCode(err); refused {
			s.warnRefusedReply(err)
			fault := frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, code, id.NodeID()))
			err = s.send(frame.Sign(fault, id), time.Now().Add(s.sendTimeoutOrDefault()), nil)
		}
		if err != nil {
			return fmt.Errorf("connection: serve_one_call: %w", err)
		}
		return nil
	case <-s.rt.endedCh:
		return fmt.Errorf("connection: serve_one_call: %w", s.endedErr())
	case <-timer.C:
		return ErrServeOneCallTimeout
	}
}

// refusalCode is the BOLT#4 code a call is answered with when its reply was
// refused before it was written, as macula_station_link's sent_or_faulted/4
// answers one: PayloadTooLarge for a reply over the frame cap, UnknownError for
// one the decoding rule would refuse. It reports false for any other error.
func refusalCode(err error) (bolt4.Code, bool) {
	switch {
	case errors.Is(err, frame.ErrFrameTooLarge):
		return bolt4.PayloadTooLarge, true
	case errors.Is(err, frame.ErrFrameBreaksDecodingRule):
		return bolt4.UnknownError, true
	default:
		return 0, false
	}
}

// warnRefusedReply logs, when the session has a logger, that a call's reply
// was refused before it was written and the call is answered with an error.
func (s *Session) warnRefusedReply(err error) {
	s.rt.mu.Lock()
	logger := s.rt.logger
	s.rt.mu.Unlock()
	if logger != nil {
		logger.Warn("macula: a call's reply was refused before it was written; answering the call with an error",
			"reason", loggable(err.Error()))
	}
}

// replyToFrame builds the reply to an inbound frame and reports whether it
// was a CALL to answer. A frame of another type, a malformed "call"-typed
// frame, or a CALL whose signature doesn't verify against the caller it
// names gets no reply. The last matches macula_station_link.erl's
// on_inbound_call/3: such a CALL never reaches a policy or a handler, so the
// caller a policy checks is the one that signed.
func replyToFrame(s *Session, value cbor.Value, lookup CallLookup, policy PolicyLookup, id identity.KeyPair) (cbor.Value, bool) {
	if frameType(value) != "call" {
		return cbor.Value{}, false
	}
	callInfo, reason := verifiedCall(value)
	if reason != "" {
		return cbor.Value{}, false
	}
	return buildCallReply(s, callInfo, lookup, policy, id), true
}

// verifiedCall parses value, a "call" frame, as a CALL whose signature
// verifies against the caller it names, or says why it can't: its signature
// first, then its fields.
func verifiedCall(value cbor.Value) (frame.CallInfo, dropReason) {
	if reason := signatureReason(value, "caller"); reason != "" {
		return frame.CallInfo{}, reason
	}
	callInfo, err := frame.ParseCall(value)
	if err != nil {
		return frame.CallInfo{}, reasonMalformed
	}
	return callInfo, ""
}

// signatureReason says why value's signature doesn't verify against the key
// in its signerField, or returns "" when it does: unsigned when the signature
// is missing or isn't 64 bytes, or the signer is missing or isn't a 32-byte
// key, and invalid_signature when both are well formed and it doesn't verify.
func signatureReason(value cbor.Value, signerField string) dropReason {
	signer := bytesField(value, signerField)
	if len(bytesField(value, "signature")) != 64 || len(signer) != 32 {
		return reasonUnsigned
	}
	if frame.Verify(value, signer) != nil {
		return reasonInvalidSignature
	}
	return ""
}

// bytesField is value's field when it holds a byte string, and nil otherwise.
func bytesField(value cbor.Value, field string) []byte {
	v, ok := value.Get(field)
	if !ok {
		return nil
	}
	b, _ := v.AsBytes()
	return b
}

// withCaller is payload as a handler receives it: a map carries caller
// under the text key "caller", replacing any entry the sender put there;
// anything else is returned unchanged.
func withCaller(payload cbor.Value, caller []byte) cbor.Value {
	entries, ok := payload.AsMap()
	if !ok {
		return payload
	}
	merged := make([]cbor.MapEntry, 0, len(entries)+1)
	for _, e := range entries {
		merged = appendUnlessCaller(merged, e)
	}
	return cbor.Map(append(merged, cbor.MapEntry{Key: cbor.Text("caller"), Val: cbor.Bytes(caller)}))
}

// appendUnlessCaller is merged with e appended, unless e's key is "caller".
func appendUnlessCaller(merged []cbor.MapEntry, e cbor.MapEntry) []cbor.MapEntry {
	if isCallerKey(e.Key) {
		return merged
	}
	return append(merged, e)
}

// isCallerKey reports whether key is the text "caller". A peer's map has no
// byte-string key to check: the decoding rule refuses such a frame first.
func isCallerKey(key cbor.Value) bool {
	text, isText := key.AsText()
	return isText && text == "caller"
}

// buildCallReply fires rpc.received_v1/rpc.replied_v1 around dispatch,
// matching macula_response.erl's own per-request child exactly: RECEIVED
// only after policy and lookup both pass (mirroring the child only
// starting once the raw advertise mechanism already decided to dispatch
// to a real handler), REPLIED for the success/handler-error outcomes but
// NOT for a handler panic -- the reference's own handle_request/2 crash
// takes down the whole per-request child before its publish_replied/2
// call is ever reached, so a crash is never announced there either, and
// this matches that omission rather than "improving" on it.
func buildCallReply(s *Session, callInfo frame.CallInfo, lookup CallLookup, policy PolicyLookup, id identity.KeyPair) cbor.Value {
	selfPub := id.NodeID()
	if err := policy(callInfo.Realm, callInfo.Procedure).Check(callInfo.UcanToken, callInfo.Caller); err != nil {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.Unauthorized, selfPub))
	}

	handler, found := lookup(callInfo.Realm, callInfo.Procedure)
	if !found {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.UnknownNextPeer, selfPub))
	}

	requestID := randomID()
	announceRPCReceived(s, callInfo.Realm, id, requestID)

	payload, err, crashed := invokeCallHandler(handler, withCaller(callInfo.Payload, callInfo.Caller))
	switch {
	case crashed:
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.TemporaryRelayFailure, selfPub))
	case err != nil:
		announceRPCReplied(s, callInfo.Realm, id, requestID, err)
		spec := frame.NewCallErrorSpec(callInfo.CallID, bolt4.UnknownError, selfPub)
		detail := err.Error()
		spec.Detail = &detail
		return frame.CallErrorFrame(spec)
	default:
		announceRPCReplied(s, callInfo.Realm, id, requestID, nil)
		return frame.Result(frame.NewResultSpec(callInfo.CallID, payload, selfPub))
	}
}

func invokeCallHandler(handler CallHandler, payload cbor.Value) (reply cbor.Value, err error, crashed bool) {
	defer func() {
		if r := recover(); r != nil {
			crashed = true
		}
	}()
	reply, err = handler(payload)
	return
}
