package stationlink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// The bounds on a call's timeout: macula's default of 5 seconds for a station
// call, and at most 10 minutes, the far edge of a provider's deadline window.
const (
	DefaultCallTimeout = 5 * time.Second
	MaxCallTimeout     = 10 * time.Minute
)

// Liveness, as macula's link probes it: a _macula.ping call to the station
// every livenessEvery, answered within livenessTimeout; two misses in a row
// end the link.
var (
	livenessEvery   = 30 * time.Second
	livenessTimeout = 30 * time.Second
)

const livenessProcedure = "_macula.ping"

var (
	// ErrCallTimeout is a call no verified reply answered within its timeout.
	ErrCallTimeout = errors.New("stationlink: no verified reply within the call's timeout")
	// ErrLivenessLost is a station that missed two liveness probes in a row.
	ErrLivenessLost = errors.New("stationlink: the station missed two liveness probes")
)

// Call is one request: the realm and procedure it names, the node it targets
// (the station itself when zero, as for _dht.* and _macula.ping; the
// provider's node_id for an org procedure), its payload, how long to wait for
// the reply, and a UCAN token and its delegation chain's proofs, when the
// procedure is gated.
type Call struct {
	Realm     [32]byte
	Procedure string
	Target    [32]byte
	Payload   cbor.Value
	Timeout   time.Duration
	Token     []byte
	Proofs    [][]byte
}

// ProviderError is a provider's ERROR for the call, verified for its request.
type ProviderError struct {
	RespondedBy [32]byte
	Code        string
	Detail      *string
}

func (e *ProviderError) Error() string {
	if e.Detail != nil {
		return fmt.Sprintf("stationlink: the provider answered %s: %s", e.Code, *e.Detail)
	}
	return "stationlink: the provider answered " + e.Code
}

// RelayError is a relay error the connected station reported for the call.
type RelayError struct {
	ReportedBy [32]byte
	Code       string
}

func (e *RelayError) Error() string {
	return "stationlink: the station could not relay the call: " + e.Code
}

// pendingCall is a call waiting for its reply.
type pendingCall struct {
	request frame.VerifiedRequest
	outcome chan callOutcome
}

type callOutcome struct {
	payload cbor.Value
	err     error
}

// Call signs c as a CALL with the link's identity key, sends it on the control
// stream, and waits for the RESULT or ERROR that verifies for it: a provider
// reply signed by its target, or a relay error the connected station signed. A
// reply that does not verify is counted in Unrouted as unverified_reply and
// ignored, and the call keeps waiting, as macula's link does.
func (l *Link) Call(ctx context.Context, c Call) (cbor.Value, error) {
	timeout := min(max(c.Timeout, 0), MaxCallTimeout)
	if timeout == 0 {
		timeout = DefaultCallTimeout
	}
	target := c.Target
	if target == ([32]byte{}) {
		target = l.station.NodeID
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return cbor.Value{}, err
	}
	signed, err := frame.SignCall(frame.RequestSpec{
		RequestID: id, Realm: c.Realm, Procedure: c.Procedure, Target: target,
		Deadline: uint64(time.Now().Add(timeout).UnixMilli()), Payload: c.Payload, Token: c.Token, Proofs: c.Proofs,
	}, l.key)
	if err != nil {
		return cbor.Value{}, err
	}
	request, err := frame.VerifyRequest(signed, l.profile)
	if err != nil {
		return cbor.Value{}, err
	}
	pending := &pendingCall{request: request, outcome: make(chan callOutcome, 1)}
	l.mu.Lock()
	l.pending[id] = pending
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.pending, id)
		l.mu.Unlock()
	}()
	if err := l.writer.write(cbor.Encode(signed), MaxFrameBytes); err != nil {
		return cbor.Value{}, err
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case outcome := <-pending.outcome:
		return outcome.payload, outcome.err
	case <-timer.C:
		return cbor.Value{}, ErrCallTimeout
	case <-ctx.Done():
		return cbor.Value{}, ctx.Err()
	case <-l.done:
		return cbor.Value{}, l.Err()
	}
}

// replied matches a RESULT or ERROR to its pending call by the ids it claims,
// and hands on the reply only once it verifies for that call's request.
func (l *Link) replied(v cbor.Value) {
	id, _, err := frame.ClaimedReplyIDs(v)
	if err != nil {
		l.count("malformed_reply")
		return
	}
	l.mu.Lock()
	pending := l.pending[id]
	l.mu.Unlock()
	if pending == nil {
		l.count("unmatched_reply")
		return
	}
	outcome, verified := l.verifiedOutcome(v, pending.request)
	if !verified {
		l.count("unverified_reply")
		return
	}
	select {
	case pending.outcome <- outcome:
	default:
	}
}

func (l *Link) verifiedOutcome(v cbor.Value, request frame.VerifiedRequest) (callOutcome, bool) {
	if _, isReply := v.Get("reply"); isReply {
		reply, err := frame.VerifyReply(v, request, l.profile)
		if err != nil {
			return callOutcome{}, false
		}
		if reply.FrameType == "result" {
			return callOutcome{payload: reply.Payload}, true
		}
		return callOutcome{err: &ProviderError{RespondedBy: reply.RespondedBy, Code: reply.Code, Detail: reply.Detail}}, true
	}
	relayed, err := frame.VerifyRelayError(v, request, l.profile, l.station.NodeID)
	if err != nil {
		return callOutcome{}, false
	}
	return callOutcome{err: &RelayError{ReportedBy: relayed.ReportedBy, Code: relayed.Code}}, true
}

// probe sends a liveness probe every livenessEvery and ends the link after two
// misses in a row. Any verified answer counts, a provider's or a relay error
// from the station alike: it proves the station is there.
func (l *Link) probe() {
	ticker := time.NewTicker(livenessEvery)
	defer ticker.Stop()
	misses := 0
	for {
		select {
		case <-l.done:
			return
		case <-ticker.C:
		}
		_, err := l.Call(context.Background(), Call{Procedure: livenessProcedure, Payload: cbor.Map(nil), Timeout: livenessTimeout})
		misses = missesAfter(err, misses)
		if misses >= 2 {
			l.end(ErrLivenessLost)
			return
		}
	}
}

// missesAfter is the count of consecutive misses after a probe's outcome: a
// timeout is one more, any verified answer starts the count again.
func missesAfter(err error, misses int) int {
	if errors.Is(err, ErrCallTimeout) {
		return misses + 1
	}
	return 0
}

func (l *Link) count(what string) {
	l.mu.Lock()
	l.unrouted[what]++
	l.mu.Unlock()
}
