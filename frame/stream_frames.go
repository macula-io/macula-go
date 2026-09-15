package frame

import (
	"bytes"
	"fmt"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The frame types of stream frames besides STREAM_ERROR, which relay errors
// share.
const (
	frameTypeStreamData  = "stream_data"
	frameTypeStreamEnd   = "stream_end"
	frameTypeStreamReply = "stream_reply"
)

// StreamFields is a stream frame as its sender gives it to SignProviderStream or
// SignCallerStream (D25 item 5): a StreamDataFields, StreamEndFields,
// StreamErrorFields or StreamReplyFields value. Each holds Seq, its sender's own
// next sequence number on the stream, from 0.
type StreamFields interface {
	streamFields()
}

// StreamDataFields is a STREAM_DATA, one chunk. A Raw body is a byte string, and
// a Msgpack body any value the wire carries.
type StreamDataFields struct {
	Seq      uint64
	Encoding StreamEncoding
	Body     cbor.Value
}

// StreamEndFields is a STREAM_END, the last frame of its sender's side: Send
// half-closes the stream, and Both closes it.
type StreamEndFields struct {
	Seq  uint64
	Role StreamRole
}

// StreamErrorFields is a STREAM_ERROR, which aborts the stream: a code of at most
// 64 bytes and a message of at most 256, both UTF-8.
type StreamErrorFields struct {
	Seq     uint64
	Code    string
	Message string
}

// StreamReplyFields is a STREAM_REPLY, a provider's terminal value for a
// client_stream or bidi stream. A caller sends none.
type StreamReplyFields struct {
	Seq     uint64
	Payload cbor.Value
}

func (StreamDataFields) streamFields()  {}
func (StreamEndFields) streamFields()   {}
func (StreamErrorFields) streamFields() {}
func (StreamReplyFields) streamFields() {}

// VerifiedStreamFrame is a stream frame that verified against its stream: its
// type, its signer's key id and its seq, with the fields of its type. Encoding
// and Body are a STREAM_DATA's, Role a STREAM_END's, Code and Message a
// STREAM_ERROR's, and Payload a STREAM_REPLY's.
type VerifiedStreamFrame struct {
	FrameType string
	Signer    [32]byte
	Seq       uint64
	Encoding  StreamEncoding
	Body      cbor.Value
	Role      StreamRole
	Code      string
	Message   string
	Payload   cbor.Value
}

// StreamState is what a verifier holds for one stream, as macula_frame's
// stream_state() holds it: the verified STREAM_OPEN and, for each side, the next
// seq and whether that side has ended, and for the provider the key and signer
// its first frame carried. VerifyProviderStream and VerifyCallerStream return
// the next state with each frame that verifies, and the state they were given
// with a refusal.
type StreamState struct {
	open     VerifiedRequest
	provider sideState
	caller   sideState
}

// sideState is one side of a stream as its verifier holds it. key and signer
// are the provider's, from its first frame.
type sideState struct {
	next   uint64
	ended  bool
	key    []byte
	signer [32]byte
}

// OpenStream is the state a verifier starts a stream with, as macula_frame's
// open_stream/1 gives it: nothing seen from either side yet. open must be a
// verified STREAM_OPEN (ErrOutOfRange).
func OpenStream(open VerifiedRequest) (StreamState, error) {
	if !isStreamOpen(open) {
		return StreamState{}, fmt.Errorf("%w: a stream opens on a STREAM_OPEN, not a %q", ErrOutOfRange, open.FrameType)
	}
	return StreamState{open: open}, nil
}

// SignProviderStream signs a provider's stream frame for a verified STREAM_OPEN
// with the provider's identity key, as macula_frame's provider_stream/3 and
// stream_bytes/2 build one: signer is the key's key id, and stream is a signed
// object under MACULA-PQ-STREAM-V1 that carries the key on the first frame, seq
// 0, and leaves it out after. It checks, in this order, and refuses a key that
// is not an identity key or whose key id is not the STREAM_OPEN's target, or an
// open that is not a verified STREAM_OPEN (ErrUnsignable); a STREAM_ERROR's code
// over 64 bytes or message over 256 (ErrTextTooLong, judged first) or not UTF-8
// (ErrInvalidText); a Msgpack body or a payload the wire cannot carry
// (CheckPayload's refusal); and a seq of 2^53 or more, an encoding or role
// outside its set, a Raw body that is not a byte string, or fields that are not
// one of the four StreamFields values (ErrOutOfRange).
func SignProviderStream(fields StreamFields, open VerifiedRequest, key *identity.NodeKey) (cbor.Value, error) {
	frameType, tbs, seq, err := streamBuild(fields, open, key, false)
	if err != nil {
		return cbor.Value{}, err
	}
	if seq == 0 {
		stream, err := identity.SignObject(streamLabel, tbs, key)
		if err != nil {
			return cbor.Value{}, err
		}
		return streamFrame(frameType, "stream", stream.Value()), nil
	}
	stream, err := identity.SignHeldObject(streamLabel, tbs, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return streamFrame(frameType, "stream", stream.Value()), nil
}

// SignCallerStream signs a caller's stream frame for a verified STREAM_OPEN with
// the caller's identity key, as macula_frame's caller_stream/3 and
// stream_bytes/2 build one: signer is the key's key id, and caller_stream is a
// signed object under MACULA-PQ-CALLER-STREAM-V1 without the key, which its
// verifier holds from the STREAM_OPEN. It runs SignProviderStream's checks with
// the STREAM_OPEN's caller as the sender, and after the key it refuses a frame a
// caller does not send (ErrNotAllowed): a STREAM_REPLY, or a STREAM_DATA in a
// server_stream.
func SignCallerStream(fields StreamFields, open VerifiedRequest, key *identity.NodeKey) (cbor.Value, error) {
	frameType, tbs, _, err := streamBuild(fields, open, key, true)
	if err != nil {
		return cbor.Value{}, err
	}
	stream, err := identity.SignHeldObject(callerStreamLabel, tbs, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return streamFrame(frameType, "caller_stream", stream.Value()), nil
}

// streamBuild runs a stream frame build's checks in macula's order: the key
// against its side's sender, the frame types its side sends, the text, the body
// or payload, then the ranges. It returns the frame's type, its signed fields
// and its seq.
func streamBuild(fields StreamFields, open VerifiedRequest, key *identity.NodeKey, caller bool) (string, []cbor.MapEntry, uint64, error) {
	if err := streamSigner(open, key, caller); err != nil {
		return "", nil, 0, err
	}
	if err := sideMaySend(fields, open, caller); err != nil {
		return "", nil, 0, err
	}
	if err := streamText(fields); err != nil {
		return "", nil, 0, err
	}
	if err := streamSendable(fields); err != nil {
		return "", nil, 0, err
	}
	return streamTBS(fields, open, key)
}

// streamSigner refuses a key that is not an identity key, an open that is not a
// verified STREAM_OPEN, and a key whose key id is not the sender the receiver
// verifies: the STREAM_OPEN's target for a provider, its caller for a caller.
func streamSigner(open VerifiedRequest, key *identity.NodeKey, caller bool) error {
	if err := identitySigner(key); err != nil {
		return err
	}
	sender := open.Target
	if caller {
		sender = open.Caller
	}
	if !isStreamOpen(open) || key.KeyID() != sender {
		return ErrUnsignable
	}
	return nil
}

// sideMaySend refuses a stream frame a caller does not send: a STREAM_REPLY, or
// a STREAM_DATA in a server_stream. A provider sends every stream frame type.
func sideMaySend(fields StreamFields, open VerifiedRequest, caller bool) error {
	if !caller {
		return nil
	}
	switch fields.(type) {
	case StreamReplyFields:
		return fmt.Errorf("%w: a caller's STREAM_REPLY", ErrNotAllowed)
	case StreamDataFields:
		if serverStream(open) {
			return fmt.Errorf("%w: a caller's STREAM_DATA in a server_stream", ErrNotAllowed)
		}
	}
	return nil
}

// streamText refuses a STREAM_ERROR's code over 64 bytes or not UTF-8, then its
// message over 256 bytes or not UTF-8.
func streamText(fields StreamFields) error {
	streamError, isError := fields.(StreamErrorFields)
	if !isError {
		return nil
	}
	if err := boundedText("code", streamError.Code, maxErrorCodeBytes); err != nil {
		return err
	}
	return boundedText("message", streamError.Message, maxErrorTextBytes)
}

// streamSendable refuses a Msgpack body or a STREAM_REPLY's payload the wire
// cannot carry.
func streamSendable(fields StreamFields) error {
	switch f := fields.(type) {
	case StreamDataFields:
		if f.Encoding == Msgpack {
			return CheckPayload(f.Body)
		}
	case StreamReplyFields:
		return CheckPayload(f.Payload)
	}
	return nil
}

// streamTBS is a stream frame's type, its signed fields and its seq, refusing
// fields outside their ranges and sets (ErrOutOfRange).
func streamTBS(fields StreamFields, open VerifiedRequest, key *identity.NodeKey) (string, []cbor.MapEntry, uint64, error) {
	frameType, typeFields, seq, err := streamTypeFields(fields)
	if err != nil {
		return "", nil, 0, err
	}
	if seq >= maxProtocolInt {
		return "", nil, 0, fmt.Errorf("%w: a seq of 2^53 or more", ErrOutOfRange)
	}
	signer := key.KeyID()
	tbs := append(typeFields,
		textEntry("frame_type", frameType),
		bytesEntry("request_id", open.RequestID[:]),
		bytesEntry("request_hash", open.RequestHash[:]),
		bytesEntry("signer", signer[:]),
		uintEntry("seq", seq))
	return frameType, tbs, seq, nil
}

// streamTypeFields is the type of a stream frame build, the fields of that type
// and its seq. It refuses an encoding or role outside its set, a Raw body that
// is not a byte string, and fields that are not one of the four StreamFields
// values (ErrOutOfRange).
func streamTypeFields(fields StreamFields) (string, []cbor.MapEntry, uint64, error) {
	switch f := fields.(type) {
	case StreamDataFields:
		_, isBytes := f.Body.AsBytes()
		switch {
		case f.Encoding != Raw && f.Encoding != Msgpack:
			return "", nil, 0, fmt.Errorf("%w: a stream encoding outside its set", ErrOutOfRange)
		case f.Encoding == Raw && !isBytes:
			return "", nil, 0, fmt.Errorf("%w: a raw body that is not a byte string", ErrOutOfRange)
		}
		return frameTypeStreamData, []cbor.MapEntry{textEntry("encoding", f.Encoding.Name()), valueEntry("body", f.Body)}, f.Seq, nil
	case StreamEndFields:
		if f.Role != Send && f.Role != Both {
			return "", nil, 0, fmt.Errorf("%w: a stream role outside its set", ErrOutOfRange)
		}
		return frameTypeStreamEnd, []cbor.MapEntry{textEntry("role", f.Role.Name())}, f.Seq, nil
	case StreamErrorFields:
		return frameTypeStreamError, []cbor.MapEntry{textEntry("code", f.Code), textEntry("message", f.Message)}, f.Seq, nil
	case StreamReplyFields:
		return frameTypeStreamReply, []cbor.MapEntry{valueEntry("payload", f.Payload)}, f.Seq, nil
	}
	return "", nil, 0, fmt.Errorf("%w: stream fields of type %T", ErrOutOfRange, fields)
}

// streamFrame is a stream frame of frameType carrying object under objectName.
func streamFrame(frameType, objectName string, object cbor.Value) cbor.Value {
	return cbor.Map([]cbor.MapEntry{
		uintEntry("version", ProtocolVersion),
		textEntry("frame_type", frameType),
		valueEntry(objectName, object),
	})
}

// VerifyProviderStream verifies a provider's received stream frame against its
// stream's state under the connection's profile p, as macula_frame's
// verify_provider_stream/3 does, and returns the frame's fields and the stream's
// next state. The frame is exactly version, frame_type and stream, of the
// protocol's version, and nothing follows the provider's STREAM_END. Before the
// provider's first frame the state holds no provider key, so a frame without one
// is out of order. The first frame's signer is the key id of the key it carries
// and the STREAM_OPEN's target, with seq 0; later frames verify with that key,
// name that signer and carry no key. Every frame names the STREAM_OPEN's
// request_id and request_hash, and has the seq after the provider's last. It
// refuses with ErrMalformedFrame, ErrStreamEnded,
// identity.ErrObjectSignatureInvalid, ErrKeyIDMismatch, ErrRequestMismatch,
// ErrNotTheTarget or ErrSeqMismatch, and in a binary without ML-DSA with
// identity.ErrPostQuantumUnavailable.
func VerifyProviderStream(v cbor.Value, state StreamState, p profile.Profile) (VerifiedStreamFrame, StreamState, error) {
	frameType, object, ok := receivedFrame(v, "stream", streamObject, nil,
		frameTypeStreamData, frameTypeStreamEnd, frameTypeStreamError, frameTypeStreamReply)
	switch {
	case !ok:
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	case state.provider.ended:
		return VerifiedStreamFrame{}, state, ErrStreamEnded
	case state.provider.key == nil:
		return providerFirst(frameType, object, state, p)
	}
	return providerLater(frameType, object, state, p)
}

// providerFirst verifies the provider's first frame, which carries its key, and
// holds that key and signer for the frames after it.
func providerFirst(frameType string, object cbor.Value, state StreamState, p profile.Profile) (VerifiedStreamFrame, StreamState, error) {
	if !carriesKey(object) {
		return VerifiedStreamFrame{}, state, ErrSeqMismatch
	}
	verified, err := identity.VerifyObject(streamLabel, object, p)
	if err != nil {
		return VerifiedStreamFrame{}, state, objectRefusal(err)
	}
	fields, ok := streamRead(frameType, verified.Fields)
	if !ok {
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	}
	frame := verifiedStreamFrame(frameType, fields)
	switch {
	case frame.Signer != identity.NodeIDOf(verified.Key, p):
		return VerifiedStreamFrame{}, state, ErrKeyIDMismatch
	case !namesRequest(fields, state.open):
		return VerifiedStreamFrame{}, state, ErrRequestMismatch
	case frame.Signer != state.open.Target:
		return VerifiedStreamFrame{}, state, ErrNotTheTarget
	case frame.Seq != 0:
		return VerifiedStreamFrame{}, state, ErrSeqMismatch
	}
	next := state
	next.provider = sideState{next: 1, ended: frameType == frameTypeStreamEnd, key: verified.Key, signer: frame.Signer}
	return frame, next, nil
}

// providerLater verifies a provider's later frame with the key its first frame
// carried. A later frame that still carries a key verifies with that key, which
// must be the held one, and is refused for its shape once its seq has been
// checked.
func providerLater(frameType string, object cbor.Value, state StreamState, p profile.Profile) (VerifiedStreamFrame, StreamState, error) {
	held, carried := state.provider, carriesKey(object)
	var verified identity.VerifiedObject
	var err error
	if carried {
		verified, err = identity.VerifyObject(streamLabel, object, p)
	} else {
		verified, err = identity.VerifyHeldObject(streamLabel, object, held.key, p)
	}
	switch {
	case err != nil:
		return VerifiedStreamFrame{}, state, objectRefusal(err)
	case !bytes.Equal(verified.Key, held.key):
		return VerifiedStreamFrame{}, state, ErrKeyIDMismatch
	}
	fields, ok := streamRead(frameType, verified.Fields)
	if !ok {
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	}
	frame := verifiedStreamFrame(frameType, fields)
	switch {
	case frame.Signer != held.signer:
		return VerifiedStreamFrame{}, state, ErrKeyIDMismatch
	case !namesRequest(fields, state.open):
		return VerifiedStreamFrame{}, state, ErrRequestMismatch
	case frame.Seq != held.next:
		return VerifiedStreamFrame{}, state, ErrSeqMismatch
	case carried:
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	}
	next := state
	next.provider.next, next.provider.ended = frame.Seq+1, frameType == frameTypeStreamEnd
	return frame, next, nil
}

// VerifyCallerStream verifies a caller's received stream frame against its
// stream's state under the connection's profile p, as macula_frame's
// verify_caller_stream/3 does, with the STREAM_OPEN's key, and returns the
// frame's fields and the stream's next state. The frame is exactly version,
// frame_type and caller_stream, of the protocol's version, a STREAM_DATA,
// STREAM_END or STREAM_ERROR, and nothing follows the caller's STREAM_END. A
// caller sends no STREAM_DATA in a server_stream. The signer is the
// STREAM_OPEN's caller, the frame names its request_id and request_hash, and its
// seq is the one after the caller's last. It refuses with ErrMalformedFrame,
// ErrStreamEnded, identity.ErrObjectSignatureInvalid, ErrKeyIDMismatch,
// ErrRequestMismatch or ErrSeqMismatch, and in a binary without ML-DSA with
// identity.ErrPostQuantumUnavailable.
func VerifyCallerStream(v cbor.Value, state StreamState, p profile.Profile) (VerifiedStreamFrame, StreamState, error) {
	frameType, object, ok := receivedFrame(v, "caller_stream", heldObject, nil,
		frameTypeStreamData, frameTypeStreamEnd, frameTypeStreamError)
	switch {
	case !ok:
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	case state.caller.ended:
		return VerifiedStreamFrame{}, state, ErrStreamEnded
	}
	verified, err := identity.VerifyHeldObject(callerStreamLabel, object, state.open.Key, p)
	if err != nil {
		return VerifiedStreamFrame{}, state, objectRefusal(err)
	}
	fields, ok := streamRead(frameType, verified.Fields)
	if !ok {
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	}
	frame := verifiedStreamFrame(frameType, fields)
	switch {
	case frameType == frameTypeStreamData && serverStream(state.open):
		return VerifiedStreamFrame{}, state, ErrMalformedFrame
	case frame.Signer != state.open.Caller:
		return VerifiedStreamFrame{}, state, ErrKeyIDMismatch
	case !namesRequest(fields, state.open):
		return VerifiedStreamFrame{}, state, ErrRequestMismatch
	case frame.Seq != state.caller.next:
		return VerifiedStreamFrame{}, state, ErrSeqMismatch
	}
	next := state
	next.caller.next, next.caller.ended = frame.Seq+1, frameType == frameTypeStreamEnd
	return frame, next, nil
}

// streamTypeFieldNames are the fields each stream frame type carries besides
// frame_type, alg, request_id, request_hash, signer and seq.
var streamTypeFieldNames = map[string][]string{
	frameTypeStreamData:  {"encoding", "body"},
	frameTypeStreamEnd:   {"role"},
	frameTypeStreamError: {"code", "message"},
	frameTypeStreamReply: {"payload"},
}

// streamRead reads a stream frame's signed fields through its type's table, as
// macula_frame's stream_read does: frame_type, request_id, request_hash, signer
// and seq, and exactly the fields of its type, a raw body a byte string.
func streamRead(frameType string, tbs cbor.Value) (map[string]cbor.Value, bool) {
	fields, ok := readFields(tbs, streamTable(frameType))
	if !ok || !hasFields(fields, "frame_type", "request_id", "request_hash", "signer", "seq") {
		return nil, false
	}
	typeFields := streamTypeFieldNames[frameType]
	carried := 5 + len(typeFields)
	if _, hasAlg := fields["alg"]; hasAlg {
		carried++
	}
	if !hasFields(fields, typeFields...) || len(fields) != carried {
		return nil, false
	}
	if frameType == frameTypeStreamData && textOf(fields["encoding"]) == Raw.Name() {
		_, isBytes := fields["body"].AsBytes()
		return fields, isBytes
	}
	return fields, true
}

func streamTable(frameType string) map[string]fieldRule {
	return map[string]fieldRule{
		"frame_type":   textIn(frameType),
		"alg":          anyValue,
		"request_id":   bytesOf(16),
		"request_hash": bytesOf(48),
		"signer":       bytesOf(32),
		"seq":          protocolUint,
		"encoding":     textIn(Raw.Name(), Msgpack.Name()),
		"body":         anyValue,
		"role":         textIn(Send.Name(), Both.Name()),
		"code":         textWithin(maxErrorCodeBytes),
		"message":      textWithin(maxErrorTextBytes),
		"payload":      anyValue,
	}
}

func verifiedStreamFrame(frameType string, fields map[string]cbor.Value) VerifiedStreamFrame {
	seq, _ := fields["seq"].AsInt64()
	frame := VerifiedStreamFrame{
		FrameType: frameType,
		Seq:       uint64(seq),
		Body:      fields["body"],
		Code:      textOf(fields["code"]),
		Message:   textOf(fields["message"]),
		Payload:   fields["payload"],
	}
	fixedBytes(frame.Signer[:], fields["signer"])
	frame.Encoding, _ = streamEncodingFromName(textOf(fields["encoding"]))
	frame.Role, _ = streamRoleFromName(textOf(fields["role"]))
	return frame
}

func isStreamOpen(open VerifiedRequest) bool {
	return open.FrameType == frameTypeStreamOpen && open.Mode != nil
}

func serverStream(open VerifiedRequest) bool {
	return open.Mode != nil && *open.Mode == ServerStream
}

// carriesKey reports whether a stream object carries its key.
func carriesKey(object cbor.Value) bool {
	_, has := object.Get("key")
	return has
}
