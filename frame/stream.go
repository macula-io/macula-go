package frame

import (
	"errors"

	"github.com/macula-io/macula-go-sdk/cbor"
)

// StreamMode is who's expected to push data on a STREAM_OPEN — matches
// macula_stream:mode().
type StreamMode int

const (
	// ServerStream: the provider pushes chunks at the caller.
	ServerStream StreamMode = iota
	// ClientStream: the caller pushes chunks at the provider (§12.3's
	// push-upload path is exactly this mode).
	ClientStream
	// Bidi: both directions.
	Bidi
)

func (m StreamMode) Name() string {
	switch m {
	case ClientStream:
		return "client_stream"
	case Bidi:
		return "bidi"
	default:
		return "server_stream"
	}
}

func streamModeFromName(name string) (StreamMode, bool) {
	switch name {
	case "server_stream":
		return ServerStream, true
	case "client_stream":
		return ClientStream, true
	case "bidi":
		return Bidi, true
	default:
		return 0, false
	}
}

// StreamEncoding is a hint on a STREAM_DATA for how to interpret body —
// not a second wire codec. body is always an ordinary nested cbor.Value
// in the frame's own canonical-CBOR envelope either way; encoding is
// purely semantic ("treat body as raw bytes" vs "treat it as a
// structured value").
type StreamEncoding int

const (
	// Raw: body is opaque bytes.
	Raw StreamEncoding = iota
	// Msgpack: body is a structured cbor.Value (despite the name -- no
	// msgpack byte-level encoding actually happens; see this type's doc).
	Msgpack
)

func (e StreamEncoding) Name() string {
	if e == Msgpack {
		return "msgpack"
	}
	return "raw"
}

func streamEncodingFromName(name string) (StreamEncoding, bool) {
	switch name {
	case "raw":
		return Raw, true
	case "msgpack":
		return Msgpack, true
	default:
		return 0, false
	}
}

// StreamRole is which direction(s) are closing on a STREAM_END.
type StreamRole int

const (
	// Send: half-close -- this side is done sending, still willing to
	// receive.
	Send StreamRole = iota
	// Both: full close -- this side is done in both directions.
	Both
)

func (r StreamRole) Name() string {
	if r == Both {
		return "both"
	}
	return "send"
}

func streamRoleFromName(name string) (StreamRole, bool) {
	switch name {
	case "send":
		return Send, true
	case "both":
		return Both, true
	default:
		return 0, false
	}
}

// StreamOpenSpec holds the fields for a STREAM_OPEN frame. Mirrors
// CALL's auth/routing shape -- deadline_ms/caller/source_route/
// retry_budget -- plus the stream-specific stream_id/mode/args.
type StreamOpenSpec struct {
	StreamID    []byte // 16 bytes
	Procedure   string
	Realm       []byte // 32 bytes
	Mode        StreamMode
	Args        cbor.Value
	DeadlineMs  int64
	Caller      []byte // 32 bytes
	SourceRoute []byte
	RetryBudget uint64
}

func NewStreamOpenSpec(streamID []byte, procedure string, realm []byte, mode StreamMode, args cbor.Value, deadlineMs int64, caller []byte) StreamOpenSpec {
	return StreamOpenSpec{StreamID: streamID, Procedure: procedure, Realm: realm, Mode: mode, Args: args, DeadlineMs: deadlineMs, Caller: caller}
}

func streamOpenValue(spec StreamOpenSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("stream_open", 0, frameID, sentAtMs)
	fields = withField(fields, "stream_id", cbor.Bytes(spec.StreamID))
	// procedure := binary() in the Erlang spec -- bytes, not text, same
	// as CALL's procedure.
	fields = withField(fields, "procedure", cbor.Bytes([]byte(spec.Procedure)))
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "mode", cbor.Text(spec.Mode.Name()))
	fields = withField(fields, "args", spec.Args)
	fields = withField(fields, "deadline_ms", cbor.Int(spec.DeadlineMs))
	fields = withField(fields, "caller", cbor.Bytes(spec.Caller))
	fields = withField(fields, "source_route", cbor.Bytes(spec.SourceRoute))
	fields = withField(fields, "retry_budget", cbor.Uint64(spec.RetryBudget))
	return cbor.Map(fields)
}

// StreamOpen builds a STREAM_OPEN frame with a fresh frame_id/sent_at_ms.
// Unsigned -- pass the result to Sign before sending.
func StreamOpen(spec StreamOpenSpec) cbor.Value {
	return streamOpenValue(spec, freshFrameID(), currentMillis())
}

// StreamOpenInfo is the fields a provider needs from an *inbound*
// STREAM_OPEN -- the first frame on a freshly-accepted dedicated stream
// (§13.2). Doesn't carry source_route/retry_budget: nothing in the
// provider role built so far acts on either.
type StreamOpenInfo struct {
	StreamID   []byte
	Procedure  string
	Realm      []byte
	Mode       StreamMode
	Args       cbor.Value
	DeadlineMs int64
	Caller     []byte
}

// ErrNotAStreamOpenFrame is returned by ParseStreamOpen when frame_type
// is not "stream_open".
var ErrNotAStreamOpenFrame = errors.New("frame_type is not \"stream_open\"")

// ParseStreamOpen parses a decoded frame as a STREAM_OPEN.
func ParseStreamOpen(v cbor.Value) (StreamOpenInfo, error) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return StreamOpenInfo{}, ErrNotAStreamOpenFrame
	}
	if t, ok := ft.AsText(); !ok || t != "stream_open" {
		return StreamOpenInfo{}, ErrNotAStreamOpenFrame
	}

	streamID, err := getBytesSized(v, "stream_id", 16)
	if err != nil {
		return StreamOpenInfo{}, err
	}
	procedureVal, ok := v.Get("procedure")
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "procedure", Err: ErrMissingField}
	}
	procedureB, ok := procedureVal.AsBytes()
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "procedure", Err: ErrWrongFieldType}
	}
	realm, err := getBytes32(v, "realm")
	if err != nil {
		return StreamOpenInfo{}, err
	}
	modeVal, ok := v.Get("mode")
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "mode", Err: ErrMissingField}
	}
	modeText, ok := modeVal.AsText()
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "mode", Err: ErrWrongFieldType}
	}
	mode, ok := streamModeFromName(modeText)
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "mode", Err: ErrWrongFieldType}
	}
	args, ok := v.Get("args")
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "args", Err: ErrMissingField}
	}
	deadlineVal, ok := v.Get("deadline_ms")
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "deadline_ms", Err: ErrMissingField}
	}
	deadlineMs, ok := deadlineVal.AsInt64()
	if !ok {
		return StreamOpenInfo{}, &ParseHelloError{Field: "deadline_ms", Err: ErrWrongFieldType}
	}
	caller, err := getBytes32(v, "caller")
	if err != nil {
		return StreamOpenInfo{}, err
	}

	return StreamOpenInfo{
		StreamID: streamID, Procedure: string(procedureB), Realm: realm, Mode: mode,
		Args: args, DeadlineMs: deadlineMs, Caller: caller,
	}, nil
}

// StreamDataSpec holds the fields for a STREAM_DATA frame -- one chunk.
// body's shape follows encoding: bytes for Raw, any structured
// cbor.Value for Msgpack (see StreamEncoding's doc on why that's still
// a plain CBOR value, not a second codec).
type StreamDataSpec struct {
	StreamID []byte
	Seq      uint64
	Encoding StreamEncoding
	Body     cbor.Value
}

func NewStreamDataSpec(streamID []byte, seq uint64, encoding StreamEncoding, body cbor.Value) StreamDataSpec {
	return StreamDataSpec{StreamID: streamID, Seq: seq, Encoding: encoding, Body: body}
}

// streamDataValue does NOT touch the base envelope's realm/call_id/
// source_route fields at all -- they stay Null, matching the reference
// exactly (confirmed directly against its own output, same as RESULT).
func streamDataValue(spec StreamDataSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("stream_data", 0, frameID, sentAtMs)
	fields = withField(fields, "stream_id", cbor.Bytes(spec.StreamID))
	fields = withField(fields, "seq", cbor.Uint64(spec.Seq))
	fields = withField(fields, "encoding", cbor.Text(spec.Encoding.Name()))
	fields = withField(fields, "body", spec.Body)
	return cbor.Map(fields)
}

// StreamData builds a STREAM_DATA frame with a fresh frame_id/sent_at_ms.
func StreamData(spec StreamDataSpec) cbor.Value {
	return streamDataValue(spec, freshFrameID(), currentMillis())
}

// StreamEndSpec holds the fields for a STREAM_END frame -- a half-close
// (Role: Send) or full close (Role: Both) of one direction.
type StreamEndSpec struct {
	StreamID []byte
	Role     StreamRole
}

func NewStreamEndSpec(streamID []byte, role StreamRole) StreamEndSpec {
	return StreamEndSpec{StreamID: streamID, Role: role}
}

func streamEndValue(spec StreamEndSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("stream_end", 0, frameID, sentAtMs)
	fields = withField(fields, "stream_id", cbor.Bytes(spec.StreamID))
	fields = withField(fields, "role", cbor.Text(spec.Role.Name()))
	return cbor.Map(fields)
}

// StreamEnd builds a STREAM_END frame with a fresh frame_id/sent_at_ms.
func StreamEnd(spec StreamEndSpec) cbor.Value {
	return streamEndValue(spec, freshFrameID(), currentMillis())
}

// StreamErrorSpec holds the fields for a STREAM_ERROR frame -- the
// explicit abort a well-behaved peer sends instead of just dropping the
// stream on any non-normal termination (§13.1 point 4). Code here is a
// free-form label (binary() in the reference), NOT a BOLT#4 numeric
// code like an ERROR (§6.4) frame's Code -- streaming aborts and
// unary-call errors use unrelated error vocabularies.
type StreamErrorSpec struct {
	StreamID []byte
	Code     string
	Message  string
}

func NewStreamErrorSpec(streamID []byte, code, message string) StreamErrorSpec {
	return StreamErrorSpec{StreamID: streamID, Code: code, Message: message}
}

func streamErrorValue(spec StreamErrorSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("stream_error", 0, frameID, sentAtMs)
	fields = withField(fields, "stream_id", cbor.Bytes(spec.StreamID))
	fields = withField(fields, "code", cbor.Bytes([]byte(spec.Code)))
	fields = withField(fields, "message", cbor.Bytes([]byte(spec.Message)))
	return cbor.Map(fields)
}

// StreamErrorFrame builds a STREAM_ERROR frame with a fresh
// frame_id/sent_at_ms.
func StreamErrorFrame(spec StreamErrorSpec) cbor.Value {
	return streamErrorValue(spec, freshFrameID(), currentMillis())
}

// StreamReplySpec holds the fields for a STREAM_REPLY frame -- the
// terminal result of a client_stream/bidi exchange, sent once by the
// provider after it has fully consumed and verified whatever the
// caller streamed.
type StreamReplySpec struct {
	StreamID    []byte
	Payload     cbor.Value
	RespondedBy []byte
}

func NewStreamReplySpec(streamID []byte, payload cbor.Value, respondedBy []byte) StreamReplySpec {
	return StreamReplySpec{StreamID: streamID, Payload: payload, RespondedBy: respondedBy}
}

func streamReplyValue(spec StreamReplySpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("stream_reply", 0, frameID, sentAtMs)
	fields = withField(fields, "stream_id", cbor.Bytes(spec.StreamID))
	fields = withField(fields, "payload", spec.Payload)
	fields = withField(fields, "responded_by", cbor.Bytes(spec.RespondedBy))
	return cbor.Map(fields)
}

// StreamReply builds a STREAM_REPLY frame with a fresh
// frame_id/sent_at_ms.
func StreamReply(spec StreamReplySpec) cbor.Value {
	return streamReplyValue(spec, freshFrameID(), currentMillis())
}

// FrameStreamID extracts a frame's stream_id field, regardless of frame
// type -- used to correlate STREAM_DATA/STREAM_END/STREAM_ERROR/
// STREAM_REPLY frames back to the STREAM_OPEN that started the
// exchange. 16 bytes, matching stream_id() :: <<_:128>>.
func FrameStreamID(v cbor.Value) ([]byte, bool) {
	fv, ok := v.Get("stream_id")
	if !ok {
		return nil, false
	}
	b, ok := fv.AsBytes()
	if !ok || len(b) != 16 {
		return nil, false
	}
	return b, true
}

// StreamEventKind discriminates the four shapes ParseStreamEvent can
// return.
type StreamEventKind int

const (
	StreamEventData StreamEventKind = iota
	StreamEventEnd
	StreamEventErr
	StreamEventReply
)

// StreamEvent is what a stream consumer actually receives -- one parsed
// STREAM_DATA/STREAM_END/STREAM_ERROR/STREAM_REPLY frame. Only the
// fields relevant to Kind are populated; the rest are zero.
type StreamEvent struct {
	Kind     StreamEventKind
	StreamID []byte

	// Kind == StreamEventData
	Seq      uint64
	Encoding StreamEncoding
	Body     cbor.Value

	// Kind == StreamEventEnd
	Role StreamRole

	// Kind == StreamEventErr
	Code    string
	Message string

	// Kind == StreamEventReply
	Payload     cbor.Value
	RespondedBy []byte
}

// ErrNotAStreamFrame is returned by ParseStreamEvent when frame_type is
// none of stream_data/stream_end/stream_error/stream_reply.
var ErrNotAStreamFrame = errors.New("frame_type is none of stream_data/stream_end/stream_error/stream_reply")

// ParseStreamEvent parses a decoded frame as one of STREAM_DATA/
// STREAM_END/STREAM_ERROR/STREAM_REPLY.
func ParseStreamEvent(v cbor.Value) (StreamEvent, error) {
	streamID, err := getBytesSized(v, "stream_id", 16)
	if err != nil {
		return StreamEvent{}, err
	}

	ft, ok := v.Get("frame_type")
	if !ok {
		return StreamEvent{}, ErrNotAStreamFrame
	}
	t, ok := ft.AsText()
	if !ok {
		return StreamEvent{}, ErrNotAStreamFrame
	}

	switch t {
	case "stream_data":
		seqVal, ok := v.Get("seq")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "seq", Err: ErrMissingField}
		}
		seq, ok := seqVal.AsInt64()
		if !ok || seq < 0 {
			return StreamEvent{}, &ParseHelloError{Field: "seq", Err: ErrWrongFieldType}
		}
		encVal, ok := v.Get("encoding")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "encoding", Err: ErrMissingField}
		}
		encText, ok := encVal.AsText()
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "encoding", Err: ErrWrongFieldType}
		}
		encoding, ok := streamEncodingFromName(encText)
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "encoding", Err: ErrWrongFieldType}
		}
		body, ok := v.Get("body")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "body", Err: ErrMissingField}
		}
		return StreamEvent{Kind: StreamEventData, StreamID: streamID, Seq: uint64(seq), Encoding: encoding, Body: body}, nil

	case "stream_end":
		roleVal, ok := v.Get("role")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "role", Err: ErrMissingField}
		}
		roleText, ok := roleVal.AsText()
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "role", Err: ErrWrongFieldType}
		}
		role, ok := streamRoleFromName(roleText)
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "role", Err: ErrWrongFieldType}
		}
		return StreamEvent{Kind: StreamEventEnd, StreamID: streamID, Role: role}, nil

	case "stream_error":
		codeVal, ok := v.Get("code")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "code", Err: ErrMissingField}
		}
		codeB, ok := codeVal.AsBytes()
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "code", Err: ErrWrongFieldType}
		}
		msgVal, ok := v.Get("message")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "message", Err: ErrMissingField}
		}
		msgB, ok := msgVal.AsBytes()
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "message", Err: ErrWrongFieldType}
		}
		return StreamEvent{Kind: StreamEventErr, StreamID: streamID, Code: string(codeB), Message: string(msgB)}, nil

	case "stream_reply":
		payload, ok := v.Get("payload")
		if !ok {
			return StreamEvent{}, &ParseHelloError{Field: "payload", Err: ErrMissingField}
		}
		respondedBy, err := getBytes32(v, "responded_by")
		if err != nil {
			return StreamEvent{}, err
		}
		return StreamEvent{Kind: StreamEventReply, StreamID: streamID, Payload: payload, RespondedBy: respondedBy}, nil

	default:
		return StreamEvent{}, ErrNotAStreamFrame
	}
}
