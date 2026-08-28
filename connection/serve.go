package connection

import (
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go-sdk/bolt4"
	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
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
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return ErrServeOneCallTimeout
		}
		value, err := s.control.RecvFrame(deadline)
		if err != nil {
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
		return s.replyToCall(callInfo, lookup, id)
	}
}

func (s *Session) replyToCall(callInfo frame.CallInfo, lookup CallLookup, id identity.KeyPair) error {
	reply := buildCallReply(callInfo, lookup, id.NodeID())
	return s.control.SendFrame(frame.Sign(reply, id))
}

func buildCallReply(callInfo frame.CallInfo, lookup CallLookup, selfPub []byte) cbor.Value {
	handler, found := lookup(callInfo.Realm, callInfo.Procedure)
	if !found {
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.UnknownNextPeer, selfPub))
	}

	payload, err, crashed := invokeCallHandler(handler, callInfo.Payload)
	switch {
	case crashed:
		return frame.CallErrorFrame(frame.NewCallErrorSpec(callInfo.CallID, bolt4.TemporaryRelayFailure, selfPub))
	case err != nil:
		spec := frame.NewCallErrorSpec(callInfo.CallID, bolt4.UnknownError, selfPub)
		detail := err.Error()
		spec.Detail = &detail
		return frame.CallErrorFrame(spec)
	default:
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
