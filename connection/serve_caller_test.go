package connection

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// These exercise replyToFrame directly (no network): an inbound CALL is
// answered only when its signature verifies against the caller it names,
// as in macula_station_link.erl's on_inbound_call/3, which drops any other
// CALL without a reply.

// inboundCall is a CALL for open.proc naming caller, signed by signer unless
// signer is nil.
func inboundCall(caller identity.KeyPair, signer *identity.KeyPair) cbor.Value {
	spec := frame.NewCallSpec(make([]byte, 16), "open.proc", make([]byte, 32), cbor.Text("hi"), time.Now().Add(time.Minute).UnixMilli(), caller.NodeID())
	call := frame.Call(spec)
	if signer == nil {
		return call
	}
	return frame.Sign(call, *signer)
}

// countingLookup serves every procedure with a handler that counts its runs.
func countingLookup(runs *int) CallLookup {
	return func(_ []byte, _ string) (CallHandler, bool) {
		return func(payload cbor.Value) (cbor.Value, error) {
			*runs++
			return payload, nil
		}, true
	}
}

func TestReplyToFrameAnswersACallSignedByItsCaller(t *testing.T) {
	selfID, caller := mustID(t), mustID(t)
	runs := 0
	if _, answered := replyToFrame(nil, inboundCall(caller, &caller), countingLookup(&runs), openPolicy, selfID); !answered || runs != 1 {
		t.Fatalf("CALL signed by its caller: answered=%v handler runs=%d, want an answer and one run", answered, runs)
	}
}

func TestReplyToFrameIgnoresACallNotSignedByItsCaller(t *testing.T) {
	selfID, caller, other := mustID(t), mustID(t), mustID(t)
	runs := 0
	if _, answered := replyToFrame(nil, inboundCall(caller, &other), countingLookup(&runs), openPolicy, selfID); answered || runs != 0 {
		t.Fatalf("CALL naming A but signed by B: answered=%v handler runs=%d, want no answer and no run", answered, runs)
	}
}

func TestReplyToFrameIgnoresAnUnsignedCall(t *testing.T) {
	selfID, caller := mustID(t), mustID(t)
	runs := 0
	if _, answered := replyToFrame(nil, inboundCall(caller, nil), countingLookup(&runs), openPolicy, selfID); answered || runs != 0 {
		t.Fatalf("unsigned CALL: answered=%v handler runs=%d, want no answer and no run", answered, runs)
	}
}
