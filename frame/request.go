package frame

import (
	"crypto/sha512"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The frame types of a request.
const (
	frameTypeCall       = "call"
	frameTypeStreamOpen = "stream_open"
)

// RequestSpec is a request as its caller gives it to SignCall or SignStreamOpen
// (D25). Mode is a STREAM_OPEN's stream mode, and nil for a CALL. Token is nil
// when the request carries none. SourceRoute (nil for none) and RetryBudget (nil
// for none) are routing fields outside the signature.
type RequestSpec struct {
	RequestID   [16]byte
	Realm       [32]byte
	Procedure   string
	Target      [32]byte
	Deadline    uint64
	Payload     cbor.Value
	Mode        *StreamMode
	Token       []byte
	SourceRoute []byte
	RetryBudget *uint64
}

// VerifiedRequest is a CALL or STREAM_OPEN whose request verified: its fields,
// the caller's key as carried, and RequestHash, the SHA-384 of its tbs. Mode is
// a STREAM_OPEN's, nil for a CALL, and Token is nil when the request carries
// none.
type VerifiedRequest struct {
	FrameType   string
	Key         []byte
	RequestHash [48]byte
	Caller      [32]byte
	RequestID   [16]byte
	Realm       [32]byte
	Procedure   string
	Target      [32]byte
	Deadline    uint64
	Payload     cbor.Value
	Mode        *StreamMode
	Token       []byte
}

// requestRoutes are the routing fields a CALL or STREAM_OPEN may carry.
var requestRoutes = map[string]fieldRule{"source_route": anyBytes, "retry_budget": protocolUint}

// SignCall signs a CALL with the caller's identity key, as macula_frame's
// call/2 and stream_bytes/2 build one: caller is the key's key id, and the
// request is a signed object under MACULA-PQ-REQUEST-V1. It checks, in this
// order, and refuses a key that is not an identity key (ErrUnsignable), a
// procedure over 512 bytes (ErrTextTooLong) or not UTF-8 (ErrInvalidText), a
// payload the wire cannot carry (CheckPayload's refusal), and a deadline or
// retry budget of 2^53 or more or a stream mode, which a CALL does not carry
// (ErrOutOfRange).
func SignCall(spec RequestSpec, key *identity.NodeKey) (cbor.Value, error) {
	return signRequest(frameTypeCall, spec, key)
}

// SignStreamOpen signs a STREAM_OPEN, which carries spec.Mode, with the
// caller's identity key, with SignCall's checks, the last of them refusing a
// mode that is nil or not one of the three stream modes (ErrOutOfRange).
func SignStreamOpen(spec RequestSpec, key *identity.NodeKey) (cbor.Value, error) {
	return signRequest(frameTypeStreamOpen, spec, key)
}

func signRequest(frameType string, spec RequestSpec, key *identity.NodeKey) (cbor.Value, error) {
	if err := requestBuildable(frameType, spec, key); err != nil {
		return cbor.Value{}, err
	}
	caller := key.KeyID()
	fields := []cbor.MapEntry{
		textEntry("frame_type", frameType),
		bytesEntry("caller", caller[:]),
		bytesEntry("request_id", spec.RequestID[:]),
		bytesEntry("realm", spec.Realm[:]),
		textEntry("procedure", spec.Procedure),
		bytesEntry("target", spec.Target[:]),
		uintEntry("deadline", spec.Deadline),
		valueEntry("payload", spec.Payload),
	}
	if spec.Mode != nil {
		fields = append(fields, textEntry("mode", spec.Mode.Name()))
	}
	if spec.Token != nil {
		fields = append(fields, bytesEntry("token", spec.Token))
	}
	request, err := identity.SignObject(requestLabel, fields, key)
	if err != nil {
		return cbor.Value{}, err
	}
	entries := []cbor.MapEntry{
		uintEntry("version", ProtocolVersion),
		textEntry("frame_type", frameType),
		valueEntry("request", request.Value()),
	}
	if spec.SourceRoute != nil {
		entries = append(entries, bytesEntry("source_route", spec.SourceRoute))
	}
	if spec.RetryBudget != nil {
		entries = append(entries, uintEntry("retry_budget", *spec.RetryBudget))
	}
	return cbor.Map(entries), nil
}

// requestBuildable runs a request build's checks in macula's order: the key,
// the procedure's text, the payload, then the ranges of the deadline, the retry
// budget and the stream mode.
func requestBuildable(frameType string, spec RequestSpec, key *identity.NodeKey) error {
	if err := identitySigner(key); err != nil {
		return err
	}
	if err := boundedText("procedure", spec.Procedure, maxProcedureBytes); err != nil {
		return err
	}
	if err := CheckPayload(spec.Payload); err != nil {
		return err
	}
	switch {
	case spec.Deadline >= maxProtocolInt || (spec.RetryBudget != nil && *spec.RetryBudget >= maxProtocolInt):
		return fmt.Errorf("%w: a deadline or retry budget of 2^53 or more", ErrOutOfRange)
	case frameType == frameTypeCall && spec.Mode != nil:
		return fmt.Errorf("%w: a CALL carries no stream mode", ErrOutOfRange)
	case frameType == frameTypeStreamOpen && (spec.Mode == nil || !knownStreamMode(*spec.Mode)):
		return fmt.Errorf("%w: a STREAM_OPEN carries one of the three stream modes", ErrOutOfRange)
	}
	return nil
}

func knownStreamMode(mode StreamMode) bool {
	return mode == ServerStream || mode == ClientStream || mode == Bidi
}

// VerifyRequest verifies a received CALL or STREAM_OPEN under the connection's
// profile p, as macula_frame's verify_request/2 does: the frame's shape, the
// request's signature and fields, and caller as the key id of its key. It
// refuses with ErrMalformedFrame, identity.ErrObjectSignatureInvalid or
// ErrKeyIDMismatch, and in a binary without ML-DSA with
// identity.ErrPostQuantumUnavailable. A station checks this before it routes,
// and a provider before its own checks, which stay with the caller: its node_id
// as target, the deadline window, replays and tokens.
func VerifyRequest(v cbor.Value, p profile.Profile) (VerifiedRequest, error) {
	frameType, object, ok := receivedFrame(v, "request", requestRoutes, frameTypeCall, frameTypeStreamOpen)
	if !ok {
		return VerifiedRequest{}, ErrMalformedFrame
	}
	verified, err := identity.VerifyObject(requestLabel, object, p)
	if err != nil {
		return VerifiedRequest{}, objectRefusal(err)
	}
	fields, ok := readFields(verified.Fields, requestTable(frameType))
	_, hasMode := fields["mode"]
	if !ok || !hasFields(fields, "frame_type", "caller", "request_id", "realm", "procedure", "target", "deadline", "payload") ||
		hasMode != (frameType == frameTypeStreamOpen) {
		return VerifiedRequest{}, ErrMalformedFrame
	}
	request := verifiedRequest(frameType, verified, fields)
	if request.Caller != identity.NodeIDOf(verified.Key, p) {
		return VerifiedRequest{}, ErrKeyIDMismatch
	}
	return request, nil
}

func verifiedRequest(frameType string, verified identity.VerifiedObject, fields map[string]cbor.Value) VerifiedRequest {
	deadline, _ := fields["deadline"].AsInt64()
	request := VerifiedRequest{
		FrameType:   frameType,
		Key:         verified.Key,
		RequestHash: sha512.Sum384(verified.TBS),
		Procedure:   textOf(fields["procedure"]),
		Deadline:    uint64(deadline),
		Payload:     fields["payload"],
	}
	fixedBytes(request.Caller[:], fields["caller"])
	fixedBytes(request.RequestID[:], fields["request_id"])
	fixedBytes(request.Realm[:], fields["realm"])
	fixedBytes(request.Target[:], fields["target"])
	if name, has := fields["mode"]; has {
		mode, _ := streamModeFromName(textOf(name))
		request.Mode = &mode
	}
	if token, has := fields["token"]; has {
		b, _ := token.AsBytes()
		request.Token = append([]byte{}, b...)
	}
	return request
}

func requestTable(frameType string) map[string]fieldRule {
	return map[string]fieldRule{
		"frame_type": textIn(frameType),
		"alg":        anyValue,
		"caller":     bytesOf(32),
		"request_id": bytesOf(16),
		"realm":      bytesOf(32),
		"procedure":  textWithin(maxProcedureBytes),
		"target":     bytesOf(32),
		"deadline":   protocolUint,
		"payload":    anyValue,
		"mode":       textIn(ServerStream.Name(), ClientStream.Name(), Bidi.Name()),
		"token":      anyBytes,
	}
}
