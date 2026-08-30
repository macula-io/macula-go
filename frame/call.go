package frame

import (
	"errors"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
)

// CallSpec holds the fields for a CALL frame — see
// plans/PLAN_WIRE_PROTOCOL.md §6.4.
type CallSpec struct {
	CallID      []byte // 16 bytes
	Procedure   string
	Realm       []byte // 32 bytes
	Payload     cbor.Value
	DeadlineMs  int64
	Caller      []byte // 32 bytes
	SourceRoute []byte // opaque §8 header; empty for a direct call
	RetryBudget uint64
	UcanToken   []byte
}

func NewCallSpec(callID []byte, procedure string, realm []byte, payload cbor.Value, deadlineMs int64, caller []byte) CallSpec {
	return CallSpec{CallID: callID, Procedure: procedure, Realm: realm, Payload: payload, DeadlineMs: deadlineMs, Caller: caller}
}

func callValue(spec CallSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("call", 0, frameID, sentAtMs)
	fields = withField(fields, "realm", cbor.Bytes(spec.Realm))
	fields = withField(fields, "call_id", cbor.Bytes(spec.CallID))
	// procedure := binary() in the Erlang spec -- bytes (major 2), not
	// text. Confirmed the hard way by macula-rust-sdk's own differential
	// vector test catching a signature mismatch from getting this wrong.
	fields = withField(fields, "procedure", cbor.Bytes([]byte(spec.Procedure)))
	fields = withField(fields, "payload", spec.Payload)
	fields = withField(fields, "deadline_ms", cbor.Int(spec.DeadlineMs))
	fields = withField(fields, "caller", cbor.Bytes(spec.Caller))
	fields = withField(fields, "source_route", cbor.Bytes(spec.SourceRoute))
	fields = withField(fields, "retry_budget", cbor.Uint64(spec.RetryBudget))
	fields = withField(fields, "ucan_token", cbor.Bytes(spec.UcanToken))
	return cbor.Map(fields)
}

// Call builds a CALL frame with a fresh frame_id/sent_at_ms.
func Call(spec CallSpec) cbor.Value { return callValue(spec, freshFrameID(), currentMillis()) }

// ResultSpec holds the fields for a RESULT frame.
type ResultSpec struct {
	CallID             []byte
	Payload            cbor.Value
	RespondedBy        []byte
	SourceRouteReverse []byte
}

func NewResultSpec(callID []byte, payload cbor.Value, respondedBy []byte) ResultSpec {
	return ResultSpec{CallID: callID, Payload: payload, RespondedBy: respondedBy}
}

// resultValue does NOT touch the base envelope's realm or source_route
// fields at all -- they stay Null, matching the reference exactly.
// source_route_reverse is a distinct field, not a rename.
func resultValue(spec ResultSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("result", 0, frameID, sentAtMs)
	fields = withField(fields, "call_id", cbor.Bytes(spec.CallID))
	fields = withField(fields, "payload", spec.Payload)
	fields = withField(fields, "responded_by", cbor.Bytes(spec.RespondedBy))
	fields = withField(fields, "source_route_reverse", cbor.Bytes(spec.SourceRouteReverse))
	return cbor.Map(fields)
}

// Result builds a RESULT frame with a fresh frame_id/sent_at_ms.
func Result(spec ResultSpec) cbor.Value { return resultValue(spec, freshFrameID(), currentMillis()) }

// CallErrorSpec holds the fields for an ERROR frame. Name is derived
// from Code automatically, not a caller-supplied field.
type CallErrorSpec struct {
	CallID             []byte
	Code               bolt4.Code
	ReportedBy         []byte
	Detail             *string
	OffendingHop       []byte // 32 bytes, or nil
	SourceRoutePartial []byte
}

func NewCallErrorSpec(callID []byte, code bolt4.Code, reportedBy []byte) CallErrorSpec {
	return CallErrorSpec{CallID: callID, Code: code, ReportedBy: reportedBy}
}

func callErrorValue(spec CallErrorSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("error", 0, frameID, sentAtMs)
	fields = withField(fields, "call_id", cbor.Bytes(spec.CallID))
	fields = withField(fields, "code", cbor.Uint64(uint64(spec.Code)))
	fields = withField(fields, "name", cbor.Text(spec.Code.Name()))
	fields = withField(fields, "reported_by", cbor.Bytes(spec.ReportedBy))
	detail := cbor.Null()
	if spec.Detail != nil {
		detail = cbor.Bytes([]byte(*spec.Detail))
	}
	fields = withField(fields, "detail", detail)
	offendingHop := cbor.Null()
	if spec.OffendingHop != nil {
		offendingHop = cbor.Bytes(spec.OffendingHop)
	}
	fields = withField(fields, "offending_hop", offendingHop)
	fields = withField(fields, "source_route_partial", cbor.Bytes(spec.SourceRoutePartial))
	return cbor.Map(fields)
}

// CallErrorFrame builds an ERROR frame with a fresh frame_id/sent_at_ms.
func CallErrorFrame(spec CallErrorSpec) cbor.Value {
	return callErrorValue(spec, freshFrameID(), currentMillis())
}

// CallResponse is the parsed RESULT or ERROR response to a CALL,
// correlated by call_id.
type CallResponse struct {
	IsError bool

	// Result fields (IsError == false)
	Payload     cbor.Value
	RespondedBy []byte

	// Error fields (IsError == true)
	Code       uint8
	Name       string
	ReportedBy []byte
	Detail     *string
}

// FrameCallID extracts a frame's call_id field, regardless of frame
// type -- used to correlate a RESULT/ERROR back to the CALL that
// requested it. 16 bytes -- NOT 32; call_id() :: <<_:128>> per spec.
func FrameCallID(v cbor.Value) ([]byte, bool) {
	fv, ok := v.Get("call_id")
	if !ok {
		return nil, false
	}
	b, ok := fv.AsBytes()
	if !ok || len(b) != 16 {
		return nil, false
	}
	return b, true
}

// CallInfo is the fields a provider needs from an *inbound* CALL — the
// counterpart to CallResponse for the receiving side. Doesn't carry
// source_route/retry_budget: nothing in the provider role built so far
// acts on either. UcanToken IS carried (added alongside package ucan's
// policy gating) — empty/nil if the caller attached none.
type CallInfo struct {
	CallID     []byte // 16 bytes
	Procedure  string
	Realm      []byte // 32 bytes
	Payload    cbor.Value
	DeadlineMs int64
	Caller     []byte // 32 bytes
	UcanToken  []byte // optional; empty if the caller attached none
}

// ErrNotACallFrame is returned by ParseCall when frame_type is not
// "call".
var ErrNotACallFrame = errors.New("frame_type is not \"call\"")

// ParseCall parses a decoded frame as a CALL — the provider-side
// counterpart to ParseCallResponse.
func ParseCall(v cbor.Value) (CallInfo, error) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return CallInfo{}, ErrNotACallFrame
	}
	if t, ok := ft.AsText(); !ok || t != "call" {
		return CallInfo{}, ErrNotACallFrame
	}

	callID, err := getBytesSized(v, "call_id", 16)
	if err != nil {
		return CallInfo{}, err
	}
	procedureVal, ok := v.Get("procedure")
	if !ok {
		return CallInfo{}, &ParseHelloError{Field: "procedure", Err: ErrMissingField}
	}
	procedureB, ok := procedureVal.AsBytes()
	if !ok {
		return CallInfo{}, &ParseHelloError{Field: "procedure", Err: ErrWrongFieldType}
	}
	realm, err := getBytes32(v, "realm")
	if err != nil {
		return CallInfo{}, err
	}
	payload, ok := v.Get("payload")
	if !ok {
		return CallInfo{}, &ParseHelloError{Field: "payload", Err: ErrMissingField}
	}
	deadlineVal, ok := v.Get("deadline_ms")
	if !ok {
		return CallInfo{}, &ParseHelloError{Field: "deadline_ms", Err: ErrMissingField}
	}
	deadlineMs, ok := deadlineVal.AsInt64()
	if !ok {
		return CallInfo{}, &ParseHelloError{Field: "deadline_ms", Err: ErrWrongFieldType}
	}
	caller, err := getBytes32(v, "caller")
	if err != nil {
		return CallInfo{}, err
	}
	var ucanToken []byte
	if uv, ok := v.Get("ucan_token"); ok {
		if ub, ok := uv.AsBytes(); ok {
			ucanToken = ub
		}
	}

	return CallInfo{
		CallID: callID, Procedure: string(procedureB), Realm: realm,
		Payload: payload, DeadlineMs: deadlineMs, Caller: caller,
		UcanToken: ucanToken,
	}, nil
}

// ErrNotAResultOrError is returned by ParseCallResponse when
// frame_type is neither "result" nor "error".
var ErrNotAResultOrError = errors.New("frame_type is neither \"result\" nor \"error\"")

// ParseCallResponse parses a decoded frame as a RESULT or ERROR
// response to a CALL.
func ParseCallResponse(v cbor.Value) (CallResponse, error) {
	ft, ok := v.Get("frame_type")
	if !ok {
		return CallResponse{}, ErrNotAResultOrError
	}
	t, ok := ft.AsText()
	if !ok {
		return CallResponse{}, ErrNotAResultOrError
	}

	switch t {
	case "result":
		payload, ok := v.Get("payload")
		if !ok {
			return CallResponse{}, &ParseHelloError{Field: "payload", Err: ErrMissingField}
		}
		respondedBy, err := getBytes32(v, "responded_by")
		if err != nil {
			return CallResponse{}, err
		}
		return CallResponse{IsError: false, Payload: payload, RespondedBy: respondedBy}, nil

	case "error":
		codeVal, ok := v.Get("code")
		if !ok {
			return CallResponse{}, &ParseHelloError{Field: "code", Err: ErrMissingField}
		}
		codeN, ok := codeVal.AsInt64()
		if !ok || codeN < 0 || codeN > 255 {
			return CallResponse{}, &ParseHelloError{Field: "code", Err: ErrWrongFieldType}
		}
		nameVal, ok := v.Get("name")
		if !ok {
			return CallResponse{}, &ParseHelloError{Field: "name", Err: ErrMissingField}
		}
		name, ok := nameVal.AsText()
		if !ok {
			return CallResponse{}, &ParseHelloError{Field: "name", Err: ErrWrongFieldType}
		}
		reportedBy, err := getBytes32(v, "reported_by")
		if err != nil {
			return CallResponse{}, err
		}
		var detail *string
		if dv, ok := v.Get("detail"); ok && !dv.IsNull() {
			db, ok := dv.AsBytes()
			if !ok {
				return CallResponse{}, &ParseHelloError{Field: "detail", Err: ErrWrongFieldType}
			}
			s := string(db)
			detail = &s
		}
		return CallResponse{
			IsError: true, Code: uint8(codeN), Name: name, ReportedBy: reportedBy, Detail: detail,
		}, nil

	default:
		return CallResponse{}, ErrNotAResultOrError
	}
}
