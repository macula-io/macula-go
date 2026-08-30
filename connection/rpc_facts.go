package connection

import (
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// RPC telemetry auto-facts, matching macula_request.erl (caller side:
// rpc.sent_v1/rpc.completed_v1) and macula_response.erl (provider side:
// rpc.received_v1/rpc.replied_v1) exactly -- same topic names, same
// request_id field (a fresh 16 random bytes per call, independent of the
// wire CALL frame's own CallID -- the reference tracks its own request
// lifecycle separately from the wire frame, and this does too), same
// realm as the call itself, fire-and-forget (a publish failure here never
// fails the underlying Call/ServeOneCallGated, matching
// macula_response.erl's own `_ = macula:publish(...), ok` and
// macula_request.erl's identical `publish/5` helper).
//
// Always on, matching the reference's own actual reachable behavior:
// `Announce' is a config field in both Erlang modules, but every
// reachable public entry point (`start_link`/`start_link_direct`,
// `advertise/5,6`) hardcodes it to `true' -- there is no way to turn it
// off in practice on the reference side, so Go doesn't expose an option
// nothing would ever set to false either.
const (
	rpcSentTopic      = "rpc.sent_v1"
	rpcCompletedTopic = "rpc.completed_v1"
	rpcReceivedTopic  = "rpc.received_v1"
	rpcRepliedTopic   = "rpc.replied_v1"
)

func announceRPCSent(s *Session, realm []byte, id identity.KeyPair, requestID []byte) {
	announceFact(s, true, realm, id, rpcSentTopic, cbor.Map(requestIDFields(requestID)))
}

// announceRPCCompleted matches macula_request.erl's outcome_fields/2:
// completed (no Go error, not a bolt4 ERROR frame) or failed (either).
// Erlang additionally has a `cancelled' outcome from its own
// gen_server-cancellable macula_request:cancel/1 -- Go's plain Call has
// no cancellation concept independent of an ordinary error/timeout at
// this layer (it takes no context.Context), so that outcome is not
// reachable here and is not fabricated.
func announceRPCCompleted(s *Session, realm []byte, id identity.KeyPair, requestID []byte, resp frame.CallResponse, err error) {
	fields := requestIDFields(requestID)
	switch {
	case err != nil:
		fields = append(fields, outcomeFailed(err.Error())...)
	case resp.IsError:
		fields = append(fields, outcomeFailed(resp.Name)...)
	default:
		fields = append(fields, cbor.MapEntry{Key: cbor.Text("outcome"), Val: cbor.Text("completed")})
	}
	announceFact(s, true, realm, id, rpcCompletedTopic, cbor.Map(fields))
}

func announceRPCReceived(s *Session, realm []byte, id identity.KeyPair, requestID []byte) {
	announceFact(s, true, realm, id, rpcReceivedTopic, cbor.Map(requestIDFields(requestID)))
}

// announceRPCReplied matches macula_response.erl's outcome_fields/2:
// replied ({ok, _}) or failed ({error, Reason}). A handler panic is
// deliberately NOT announced here at all -- matching the reference
// exactly, where a crashing Module:handle_request/2 crashes the whole
// per-request child before its own publish_replied/2 call is ever
// reached, so REQUEST_REPLIED is never published for a crash either.
func announceRPCReplied(s *Session, realm []byte, id identity.KeyPair, requestID []byte, handlerErr error) {
	fields := requestIDFields(requestID)
	if handlerErr != nil {
		fields = append(fields, outcomeFailed(handlerErr.Error())...)
	} else {
		fields = append(fields, cbor.MapEntry{Key: cbor.Text("outcome"), Val: cbor.Text("replied")})
	}
	announceFact(s, true, realm, id, rpcRepliedTopic, cbor.Map(fields))
}

func requestIDFields(requestID []byte) []cbor.MapEntry {
	return []cbor.MapEntry{{Key: cbor.Text("request_id"), Val: cbor.Bytes(requestID)}}
}

func outcomeFailed(reason string) []cbor.MapEntry {
	return []cbor.MapEntry{
		{Key: cbor.Text("outcome"), Val: cbor.Text("failed")},
		{Key: cbor.Text("reason"), Val: cbor.Text(reason)},
	}
}
