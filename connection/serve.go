package connection

import (
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go-sdk/bolt4"
	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/ucan"
)

// CallHandler answers one inbound CALL. Returning (payload, nil) sends
// a RESULT; returning (_, err) sends an ERROR (BOLT#4 UnknownError,
// detail=err.Error()); a panic inside the handler is recovered and
// sent as ERROR TemporaryRelayFailure — matching
// macula_station_link.erl's own safe_invoke_handler mapping exactly
// (including sending no detail on a crash, since the reference doesn't
// either — it only logs locally).
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
// macula_station_link.erl's handle_inbound_call/2 exactly: an open
// policy (the default, ucan.Open) behaves identically to plain
// ServeOneCall; a ucan.Required policy demands a CALL's UcanToken verify
// against the required issuer, and refuses with BOLT#4 Unauthorized
// (0x10) WITHOUT ever invoking lookup or a handler if it doesn't — a
// CallHandler never sees the raw token either way, matching the
// reference's own handler contract (payload only).
func (s *Session) ServeOneCallGated(lookup CallLookup, policy PolicyLookup, id identity.KeyPair, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return ErrServeOneCallTimeout
		}
		value, err := s.control.RecvFrame(deadline)
		if err != nil {
			if isRecvTimeout(err) {
				// A read-deadline timeout IS "timeout elapses with no
				// inbound CALL frame arriving" -- this used to fall
				// through to the generic wrap below instead, so
				// ErrServeOneCallTimeout was never actually reachable
				// on the ordinary "nothing arrived" path, only on the
				// narrow race where a non-call frame arrives right at
				// the deadline and the loop's own re-check catches it.
				// ServeForever depends on this sentinel to tell "keep
				// looping" apart from "the connection actually died".
				return ErrServeOneCallTimeout
			}
			return fmt.Errorf("connection: serve_one_call: %w", err)
		}
		ft, ok := value.Get("frame_type")
		if !ok {
			continue
		}
		if t, _ := ft.AsText(); t != "call" {
			continue // not ours -- see this method's doc on the limitation
		}
		callInfo, err := frame.ParseCall(value)
		if err != nil {
			continue // a malformed "call"-typed frame -- ignore and keep serving
		}
		return s.replyToCall(callInfo, lookup, policy, id)
	}
}

func (s *Session) replyToCall(callInfo frame.CallInfo, lookup CallLookup, policy PolicyLookup, id identity.KeyPair) error {
	reply := buildCallReply(s, callInfo, lookup, policy, id)
	return s.control.SendFrame(frame.Sign(reply, id))
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
	if err := policy(callInfo.Realm, callInfo.Procedure).Check(callInfo.UcanToken); err != nil {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.Unauthorized, selfPub))
	}

	handler, found := lookup(callInfo.Realm, callInfo.Procedure)
	if !found {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.UnknownNextPeer, selfPub))
	}

	requestID := randomID()
	announceRPCReceived(s, callInfo.Realm, id, requestID)

	payload, err, crashed := invokeCallHandler(handler, callInfo.Payload)
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
