package stationlink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/internal/redact"
	"github.com/macula-io/macula-go/seal"
)

// The bounds on a call's timeout: macula's default of 5 seconds for a station
// call, and at most 10 minutes, the far edge of a provider's deadline window.
const (
	DefaultCallTimeout = 5 * time.Second
	MaxCallTimeout     = 10 * time.Minute
)

// Liveness, as macula's link probes it: a liveness_ping to the station every
// livenessEvery, answered with its liveness_pong within livenessTimeout; two
// misses in a row end the link.
var (
	livenessEvery   = 30 * time.Second
	livenessTimeout = 30 * time.Second
)

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
	// SealTo is the provider's KEM key as carried, from its verified
	// advertisement: the call's payload is sealed to it, and only a sealed
	// answer, or from the clear a relay error, a refusal from the closed set
	// or sealed_refused, answers it.
	SealTo []byte
	// Clear sends the call in the clear, the application's own decision.
	// A call to a provider states SealTo or Clear, never both; one that
	// states neither is refused no_signed_state. A call to the connected
	// station needs neither.
	Clear bool
}

// String writes the Call without its credential: the grant and proofs
// show by size only.
func (c Call) String() string { return redact.Struct(c, "Token", "Proofs") }

// Format writes it as String does, whatever the verb, so %+v and %#v never
// print the credential either.
func (c Call) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, c.String()) }

// LogValue writes it as String does, so slog's JSON handler, which never
// asks fmt, does not print the credential either.
func (c Call) LogValue() slog.Value { return slog.StringValue(c.String()) }

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
	// seal is a sealed call's keys, nil for a clear one.
	seal    *callSeal
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
	if err := l.stated(c.Target, c.SealTo, c.Clear); err != nil {
		return cbor.Value{}, err
	}
	id, pending, wire, err := l.prepareCall(c)
	if err != nil {
		return cbor.Value{}, err
	}
	l.mu.Lock()
	l.pending[id] = pending
	l.mu.Unlock()
	defer l.forgetCall(id)
	if err := l.writer.write(cbor.Encode(wire), MaxFrameBytes); err != nil {
		return cbor.Value{}, err
	}
	timer := time.NewTimer(callTimeout(c.Timeout))
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

// callTimeout is a call's deadline, clamped to MaxCallTimeout and defaulted.
func callTimeout(t time.Duration) time.Duration {
	timeout := min(max(t, 0), MaxCallTimeout)
	if timeout == 0 {
		return DefaultCallTimeout
	}
	return timeout
}

// prepareCall signs c as a CALL and returns the request id, the pending entry
// that waits for its reply, and the frame to send.
func (l *Link) prepareCall(c Call) ([16]byte, *pendingCall, cbor.Value, error) {
	target := c.Target
	if target == ([32]byte{}) {
		target = l.station.NodeID
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return id, nil, cbor.Value{}, err
	}
	spec := frame.RequestSpec{
		RequestID: id, Realm: c.Realm, Procedure: c.Procedure, Target: target,
		Deadline: uint64(time.Now().Add(callTimeout(c.Timeout)).UnixMilli()), Payload: c.Payload, Token: c.Token, Proofs: c.Proofs,
	}
	var sealing *callSeal
	if c.SealTo != nil {
		s, err := l.sealRequest(&spec, seal.FrameCall, c.SealTo)
		if err != nil {
			return id, nil, cbor.Value{}, err
		}
		sealing = s
	}
	signed, err := frame.SignCall(spec, l.key)
	if err != nil {
		return id, nil, cbor.Value{}, err
	}
	request, err := frame.VerifyRequest(signed, l.profile)
	if err != nil {
		return id, nil, cbor.Value{}, err
	}
	return id, &pendingCall{request: request, seal: sealing, outcome: make(chan callOutcome, 1)}, signed, nil
}

// forgetCall drops a call's pending entry once it is over.
func (l *Link) forgetCall(id [16]byte) {
	l.mu.Lock()
	delete(l.pending, id)
	l.mu.Unlock()
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
	outcome, err := l.verifiedOutcome(v, pending)
	switch {
	case errors.Is(err, frame.ErrEnumUnknown):
		// A reply or relay error carrying an enum value this library does
		// not know is refused by name (WIRE_1_0.md section 3.4).
		l.count("enum_unknown")
		return
	case err != nil:
		l.count("unverified_reply")
		return
	}
	select {
	case pending.outcome <- outcome:
	default:
	}
}

func (l *Link) verifiedOutcome(v cbor.Value, pending *pendingCall) (callOutcome, error) {
	if _, isReply := v.Get("reply"); isReply {
		return l.verifiedReply(v, pending)
	}
	relayed, err := frame.VerifyRelayError(v, pending.request, l.profile, l.station.NodeID)
	if err != nil {
		return callOutcome{}, err
	}
	return callOutcome{err: &RelayError{ReportedBy: relayed.ReportedBy, Code: relayed.Code}}, nil
}

// verifiedReply is a RESULT or ERROR, matched to the call's request and, when
// the call was sealed, opened with the seal it was sent under.
func (l *Link) verifiedReply(v cbor.Value, pending *pendingCall) (callOutcome, error) {
	request := pending.request
	reply, err := frame.VerifyReply(v, request, l.profile)
	if err != nil {
		return callOutcome{}, err
	}
	switch {
	case pending.seal != nil:
		return pending.seal.sealedOutcome(reply, request.RequestHash), nil
	case reply.Sealed != nil:
		// This node sealed nothing, so a sealed reply answers no request it
		// made as the provider sealed it.
		return callOutcome{err: &ProviderError{RespondedBy: reply.RespondedBy, Code: codeSealedRefused}}, nil
	case reply.FrameType == "result":
		return callOutcome{payload: reply.Payload}, nil
	}
	return callOutcome{err: &ProviderError{RespondedBy: reply.RespondedBy, Code: reply.Code, Detail: reply.Detail}}, nil
}

// probe sends a liveness probe every livenessEvery and ends the link after two
// misses in a row: a liveness_ping, answered by the station's connection with a
// liveness_pong of its nonce, and nothing is signed.
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
		misses = missesAfter(l.probeOnce(), misses)
		if misses >= 2 {
			l.end(ErrLivenessLost)
			return
		}
	}
}

// probeOnce is one liveness probe: nil when answered, ErrCallTimeout when not
// within livenessTimeout.
func (l *Link) probeOnce() error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	// A pong that arrived after its probe's deadline must not take the place of
	// this probe's.
	select {
	case <-l.pongs:
	default:
	}
	if err := l.sendControl(frame.LivenessPingFrame(nonce)); err != nil {
		return err
	}
	deadline := time.After(livenessTimeout)
	for {
		select {
		case answered := <-l.pongs:
			if answered == nonce {
				return nil
			}
		case <-deadline:
			return ErrCallTimeout
		case <-l.done:
			return ErrClosed
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
