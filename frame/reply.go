package frame

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The frame types of replies and relay errors.
const (
	frameTypeResult      = "result"
	frameTypeError       = "error"
	frameTypeStreamError = "stream_error"
)

// The routing fields a reply and a relay error may carry.
var (
	replyRoutes      = map[string]fieldRule{"source_route_reverse": anyBytes}
	relayErrorRoutes = map[string]fieldRule{"source_route_partial": anyBytes}
)

// VerifiedReply is a provider's RESULT or ERROR that verified for its request:
// the node that responded, a RESULT's payload, and an ERROR's code and detail,
// nil when it carries none.
type VerifiedReply struct {
	FrameType   string
	RespondedBy [32]byte
	Payload     cbor.Value
	Code        string
	Detail      *string
}

// RelayErrorSpec is a station's relay error as it gives it to SignRelayError: an
// ERROR or STREAM_ERROR for a pending verified request, with a code from the
// closed set and no free text, and the hop that failed, nil for none.
// SourceRoutePartial is a routing field outside the signature, nil for none.
type RelayErrorSpec struct {
	FrameType          string
	Request            VerifiedRequest
	Code               string
	OffendingHop       *[32]byte
	SourceRoutePartial []byte
}

// VerifiedRelayError is a relay error that verified for its request: the
// station that reported it, its code, and the hop that failed, nil for none.
type VerifiedRelayError struct {
	FrameType    string
	ReportedBy   [32]byte
	Code         string
	OffendingHop *[32]byte
}

// SignResult signs a provider's RESULT for a verified request, as macula_frame's
// result/2 and stream_bytes/2 build one: responded_by is the key's key id, and
// the reply is a signed object under MACULA-PQ-REPLY-V1. The key must be an
// identity key whose key id is the request's target (ErrUnsignable), and the
// payload one the wire carries. sourceRouteReverse is a routing field outside
// the signature, nil for none.
func SignResult(request VerifiedRequest, payload cbor.Value, sourceRouteReverse []byte, key *identity.NodeKey) (cbor.Value, error) {
	if err := replySigner(request, key); err != nil {
		return cbor.Value{}, err
	}
	if err := CheckPayload(payload); err != nil {
		return cbor.Value{}, err
	}
	return signReply(frameTypeResult, request, []cbor.MapEntry{valueEntry("payload", payload)}, sourceRouteReverse, key)
}

// SignProviderError signs a provider's ERROR for a verified request, with
// SignResult's key check: a code of at most 64 bytes and a detail, nil for none,
// of at most 256, both UTF-8 (ErrTextTooLong, judged first, and ErrInvalidText).
func SignProviderError(request VerifiedRequest, code string, detail *string, sourceRouteReverse []byte, key *identity.NodeKey) (cbor.Value, error) {
	if err := replySigner(request, key); err != nil {
		return cbor.Value{}, err
	}
	if err := boundedText("code", code, maxErrorCodeBytes); err != nil {
		return cbor.Value{}, err
	}
	fields := []cbor.MapEntry{textEntry("code", code)}
	if detail != nil {
		if err := boundedText("detail", *detail, maxErrorTextBytes); err != nil {
			return cbor.Value{}, err
		}
		fields = append(fields, textEntry("detail", *detail))
	}
	return signReply(frameTypeError, request, fields, sourceRouteReverse, key)
}

// replySigner refuses a key that is not an identity key, or whose key id is not
// the request's target, the sender a receiver verifies.
func replySigner(request VerifiedRequest, key *identity.NodeKey) error {
	if err := identitySigner(key); err != nil {
		return err
	}
	if key.KeyID() != request.Target {
		return ErrUnsignable
	}
	return nil
}

func signReply(frameType string, request VerifiedRequest, fields []cbor.MapEntry, sourceRouteReverse []byte, key *identity.NodeKey) (cbor.Value, error) {
	respondedBy := key.KeyID()
	tbs := append(fields,
		textEntry("frame_type", frameType),
		bytesEntry("request_id", request.RequestID[:]),
		bytesEntry("request_hash", request.RequestHash[:]),
		bytesEntry("responded_by", respondedBy[:]))
	reply, err := identity.SignObject(replyLabel, tbs, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return routedFrame(frameType, "reply", reply, "source_route_reverse", sourceRouteReverse), nil
}

// VerifyReply verifies a received RESULT or provider ERROR for the request it
// answers, as macula_frame's verify_reply/3 does: the frame's shape, the reply's
// signature and fields, responded_by as the key id of its key, the request's
// request_id and request_hash, and responded_by as the request's target. It
// refuses with ErrMalformedFrame, identity.ErrObjectSignatureInvalid,
// ErrKeyIDMismatch, ErrRequestMismatch or ErrNotTheTarget, and in a binary
// without ML-DSA with identity.ErrPostQuantumUnavailable.
func VerifyReply(v cbor.Value, request VerifiedRequest, p profile.Profile) (VerifiedReply, error) {
	frameType, object, ok := receivedFrame(v, "reply", carriedObject, replyRoutes, frameTypeResult, frameTypeError)
	if !ok {
		return VerifiedReply{}, ErrMalformedFrame
	}
	verified, err := identity.VerifyObject(replyLabel, object, p)
	if err != nil {
		return VerifiedReply{}, objectRefusal(err)
	}
	fields, ok := readFields(verified.Fields, replyTable(frameType))
	if !ok || !hasFields(fields, "frame_type", "request_id", "request_hash", "responded_by") || !replyShaped(frameType, fields) {
		return VerifiedReply{}, ErrMalformedFrame
	}
	reply := VerifiedReply{FrameType: frameType, Payload: fields["payload"], Code: textOf(fields["code"]), Detail: optionalText(fields, "detail")}
	fixedBytes(reply.RespondedBy[:], fields["responded_by"])
	switch {
	case reply.RespondedBy != identity.NodeIDOf(verified.Key, p):
		return VerifiedReply{}, ErrKeyIDMismatch
	case !namesRequest(fields, request):
		return VerifiedReply{}, ErrRequestMismatch
	case reply.RespondedBy != request.Target:
		return VerifiedReply{}, ErrNotTheTarget
	}
	return reply, nil
}

// replyShaped reports whether a reply's fields are its type's: a RESULT's
// payload without a code or detail, an ERROR's code without a payload.
func replyShaped(frameType string, fields map[string]cbor.Value) bool {
	_, hasPayload := fields["payload"]
	_, hasCode := fields["code"]
	_, hasDetail := fields["detail"]
	if frameType == frameTypeResult {
		return hasPayload && !hasCode && !hasDetail
	}
	return hasCode && !hasPayload
}

func replyTable(frameType string) map[string]fieldRule {
	return map[string]fieldRule{
		"frame_type":   textIn(frameType),
		"alg":          anyValue,
		"request_id":   bytesOf(16),
		"request_hash": bytesOf(48),
		"responded_by": bytesOf(32),
		"payload":      anyValue,
		"code":         textWithin(maxErrorCodeBytes),
		"detail":       textWithin(maxErrorTextBytes),
	}
}

// SignRelayError signs a station's relay error, an ERROR or STREAM_ERROR for a
// pending request, with the station's identity key, as macula_frame's
// relay_error/2 and stream_bytes/2 build one: reported_by is the key's key id,
// and the relay error is a signed object under MACULA-PQ-RELAY-ERROR-V1. It
// checks, in this order, and refuses a key that is not an identity key
// (ErrUnsignable), a code outside the closed set (ErrRelayCodeOutsideItsSet),
// and a frame type other than error or stream_error (ErrOutOfRange).
func SignRelayError(spec RelayErrorSpec, key *identity.NodeKey) (cbor.Value, error) {
	if err := identitySigner(key); err != nil {
		return cbor.Value{}, err
	}
	if !slices.Contains(relayCodes, spec.Code) {
		return cbor.Value{}, fmt.Errorf("%w: %q", ErrRelayCodeOutsideItsSet, spec.Code)
	}
	if spec.FrameType != frameTypeError && spec.FrameType != frameTypeStreamError {
		return cbor.Value{}, fmt.Errorf("%w: relay error frame type %q", ErrOutOfRange, spec.FrameType)
	}
	reportedBy := key.KeyID()
	tbs := []cbor.MapEntry{
		textEntry("frame_type", spec.FrameType),
		bytesEntry("request_id", spec.Request.RequestID[:]),
		bytesEntry("request_hash", spec.Request.RequestHash[:]),
		bytesEntry("reported_by", reportedBy[:]),
		textEntry("code", spec.Code),
	}
	if spec.OffendingHop != nil {
		tbs = append(tbs, bytesEntry("offending_hop", spec.OffendingHop[:]))
	}
	relayError, err := identity.SignObject(relayErrorLabel, tbs, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return routedFrame(spec.FrameType, "relay_error", relayError, "source_route_partial", spec.SourceRoutePartial), nil
}

// VerifyRelayError verifies a received relay error for the pending request it
// names, from the station the connection authenticated, as macula_frame's
// verify_relay_error/4 does: the frame's shape, the relay error's signature and
// fields, reported_by as the key id of its key, the request's request_id and
// request_hash, and reported_by as expectedReporter, that station's node_id. It
// refuses with ErrMalformedFrame, identity.ErrObjectSignatureInvalid,
// ErrKeyIDMismatch, ErrRequestMismatch or ErrNotTheConnection, and in a binary
// without ML-DSA with identity.ErrPostQuantumUnavailable.
func VerifyRelayError(v cbor.Value, request VerifiedRequest, p profile.Profile, expectedReporter [32]byte) (VerifiedRelayError, error) {
	frameType, object, ok := receivedFrame(v, "relay_error", carriedObject, relayErrorRoutes, frameTypeError, frameTypeStreamError)
	if !ok {
		return VerifiedRelayError{}, ErrMalformedFrame
	}
	verified, err := identity.VerifyObject(relayErrorLabel, object, p)
	if err != nil {
		return VerifiedRelayError{}, objectRefusal(err)
	}
	fields, ok := readFields(verified.Fields, relayErrorTable(frameType))
	if !ok || !hasFields(fields, "frame_type", "request_id", "request_hash", "reported_by", "code") {
		return VerifiedRelayError{}, ErrMalformedFrame
	}
	relayError := VerifiedRelayError{FrameType: frameType, Code: textOf(fields["code"])}
	fixedBytes(relayError.ReportedBy[:], fields["reported_by"])
	if hop, has := fields["offending_hop"]; has {
		relayError.OffendingHop = new([32]byte)
		fixedBytes(relayError.OffendingHop[:], hop)
	}
	switch {
	case relayError.ReportedBy != identity.NodeIDOf(verified.Key, p):
		return VerifiedRelayError{}, ErrKeyIDMismatch
	case !namesRequest(fields, request):
		return VerifiedRelayError{}, ErrRequestMismatch
	case relayError.ReportedBy != expectedReporter:
		return VerifiedRelayError{}, ErrNotTheConnection
	}
	return relayError, nil
}

func relayErrorTable(frameType string) map[string]fieldRule {
	return map[string]fieldRule{
		"frame_type":    textIn(frameType),
		"alg":           anyValue,
		"request_id":    bytesOf(16),
		"request_hash":  bytesOf(48),
		"reported_by":   bytesOf(32),
		"code":          textIn(relayCodes...),
		"offending_hop": bytesOf(32),
	}
}

// ClaimedReplyIDs is the request_id and request_hash a received reply names,
// read without verifying it, as macula_frame's claimed_reply_ids/1 reads them: a
// RESULT or ERROR carrying reply, or an ERROR or STREAM_ERROR carrying
// relay_error. The ids are a key for finding the pending request and nothing
// more: VerifyReply or VerifyRelayError against that request decides whether the
// frame answers it. The frame's fields and the signed object's shape are checked
// as the verifiers check them, and the tbs is read with the same strict decoding
// and field table, so ids of another length or shape never come back. Neither
// the object's key nor its size for a profile is checked. Anything else is
// ErrMalformedFrame.
func ClaimedReplyIDs(v cbor.Value) ([16]byte, [48]byte, error) {
	frameTypeValue, _ := v.Get("frame_type")
	frameType := textOf(frameTypeValue)
	_, hasReply := v.Get("reply")
	_, hasRelayError := v.Get("relay_error")
	switch {
	case hasReply && (frameType == frameTypeResult || frameType == frameTypeError):
		return claimedIDs(v, frameType, "reply", replyRoutes, replyTable(frameType))
	case hasRelayError && (frameType == frameTypeError || frameType == frameTypeStreamError):
		return claimedIDs(v, frameType, "relay_error", relayErrorRoutes, relayErrorTable(frameType))
	}
	return [16]byte{}, [48]byte{}, ErrMalformedFrame
}

func claimedIDs(v cbor.Value, frameType, objectName string, routes, table map[string]fieldRule) ([16]byte, [48]byte, error) {
	_, object, ok := receivedFrame(v, objectName, carriedObject, routes, frameType)
	if !ok {
		return [16]byte{}, [48]byte{}, ErrMalformedFrame
	}
	parsed, err := identity.ParseObject(object)
	if err != nil {
		return [16]byte{}, [48]byte{}, ErrMalformedFrame
	}
	tbs, err := cbor.Decode(parsed.TBS)
	if err != nil {
		return [16]byte{}, [48]byte{}, ErrMalformedFrame
	}
	fields, ok := readFields(tbs, table)
	if !ok || !hasFields(fields, "frame_type", "request_id", "request_hash") {
		return [16]byte{}, [48]byte{}, ErrMalformedFrame
	}
	var requestID [16]byte
	var requestHash [48]byte
	fixedBytes(requestID[:], fields["request_id"])
	fixedBytes(requestHash[:], fields["request_hash"])
	return requestID, requestHash, nil
}

// namesRequest reports whether a reply's or relay error's request_id and
// request_hash are request's.
func namesRequest(fields map[string]cbor.Value, request VerifiedRequest) bool {
	requestID, _ := fields["request_id"].AsBytes()
	requestHash, _ := fields["request_hash"].AsBytes()
	return bytes.Equal(requestID, request.RequestID[:]) && bytes.Equal(requestHash, request.RequestHash[:])
}

// routedFrame is a frame of frameType carrying object under objectName, with
// the routing field routeName when route is not nil.
func routedFrame(frameType, objectName string, object identity.Object, routeName string, route []byte) cbor.Value {
	entries := []cbor.MapEntry{
		uintEntry("version", ProtocolVersion),
		textEntry("frame_type", frameType),
		valueEntry(objectName, object.Value()),
	}
	if route != nil {
		entries = append(entries, bytesEntry(routeName, route))
	}
	return cbor.Map(entries)
}
