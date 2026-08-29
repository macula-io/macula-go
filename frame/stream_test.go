package frame

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go-sdk/cbor"
)

func mkID(b byte, n int) []byte {
	id := make([]byte, n)
	for i := range id {
		id[i] = b
	}
	return id
}

func TestStreamOpenRoundTrips(t *testing.T) {
	spec := NewStreamOpenSpec(mkID(1, 16), "tube.upload", mkID(2, 32), ClientStream, cbor.Text("hi"), 12345, mkID(3, 32))
	v := StreamOpen(spec)

	info, err := ParseStreamOpen(v)
	if err != nil {
		t.Fatalf("ParseStreamOpen: %v", err)
	}
	if !bytes.Equal(info.StreamID, spec.StreamID) {
		t.Errorf("StreamID mismatch")
	}
	if info.Procedure != spec.Procedure {
		t.Errorf("Procedure = %q, want %q", info.Procedure, spec.Procedure)
	}
	if !bytes.Equal(info.Realm, spec.Realm) {
		t.Errorf("Realm mismatch")
	}
	if info.Mode != ClientStream {
		t.Errorf("Mode = %v, want ClientStream", info.Mode)
	}
	if txt, ok := info.Args.AsText(); !ok || txt != "hi" {
		t.Errorf("Args = %v, want Text(hi)", info.Args)
	}
	if info.DeadlineMs != 12345 {
		t.Errorf("DeadlineMs = %d, want 12345", info.DeadlineMs)
	}
	if !bytes.Equal(info.Caller, spec.Caller) {
		t.Errorf("Caller mismatch")
	}
}

func TestStreamOpenRejectsWrongFrameType(t *testing.T) {
	other := Goodbye("bye", nil)
	if _, err := ParseStreamOpen(other); err != ErrNotAStreamOpenFrame {
		t.Errorf("ParseStreamOpen(non-stream_open) = %v, want ErrNotAStreamOpenFrame", err)
	}
}

func TestParseStreamEventData(t *testing.T) {
	spec := NewStreamDataSpec(mkID(9, 16), 42, Msgpack, cbor.Uint64(7), nil)
	v := StreamData(spec)

	ev, err := ParseStreamEvent(v)
	if err != nil {
		t.Fatalf("ParseStreamEvent: %v", err)
	}
	if ev.Kind != StreamEventData {
		t.Fatalf("Kind = %v, want StreamEventData", ev.Kind)
	}
	if !bytes.Equal(ev.StreamID, spec.StreamID) {
		t.Errorf("StreamID mismatch")
	}
	if ev.Seq != 42 {
		t.Errorf("Seq = %d, want 42", ev.Seq)
	}
	if ev.Encoding != Msgpack {
		t.Errorf("Encoding = %v, want Msgpack", ev.Encoding)
	}
	if n, ok := ev.Body.AsInt64(); !ok || n != 7 {
		t.Errorf("Body = %v, want Uint64(7)", ev.Body)
	}
}

func TestParseStreamEventEnd(t *testing.T) {
	spec := NewStreamEndSpec(mkID(9, 16), Both, nil)
	v := StreamEnd(spec)

	ev, err := ParseStreamEvent(v)
	if err != nil {
		t.Fatalf("ParseStreamEvent: %v", err)
	}
	if ev.Kind != StreamEventEnd {
		t.Fatalf("Kind = %v, want StreamEventEnd", ev.Kind)
	}
	if ev.Role != Both {
		t.Errorf("Role = %v, want Both", ev.Role)
	}
}

func TestParseStreamEventError(t *testing.T) {
	spec := NewStreamErrorSpec(mkID(9, 16), "cancelled", "user aborted", nil)
	v := StreamErrorFrame(spec)

	ev, err := ParseStreamEvent(v)
	if err != nil {
		t.Fatalf("ParseStreamEvent: %v", err)
	}
	if ev.Kind != StreamEventErr {
		t.Fatalf("Kind = %v, want StreamEventErr", ev.Kind)
	}
	if ev.Code != "cancelled" || ev.Message != "user aborted" {
		t.Errorf("Code/Message = %q/%q, want cancelled/user aborted", ev.Code, ev.Message)
	}
}

func TestParseStreamEventReply(t *testing.T) {
	spec := NewStreamReplySpec(mkID(9, 16), cbor.Text("done"), mkID(4, 32))
	v := StreamReply(spec)

	ev, err := ParseStreamEvent(v)
	if err != nil {
		t.Fatalf("ParseStreamEvent: %v", err)
	}
	if ev.Kind != StreamEventReply {
		t.Fatalf("Kind = %v, want StreamEventReply", ev.Kind)
	}
	if txt, ok := ev.Payload.AsText(); !ok || txt != "done" {
		t.Errorf("Payload = %v, want Text(done)", ev.Payload)
	}
	if !bytes.Equal(ev.RespondedBy, spec.RespondedBy) {
		t.Errorf("RespondedBy mismatch")
	}
}

func TestStreamDataEndErrorReplyLeaveRealmCallIdSourceRouteNull(t *testing.T) {
	// Matches RESULT's own documented behavior: these four frame types
	// don't touch the base envelope's realm/call_id/source_route at all.
	for name, v := range map[string]cbor.Value{
		"stream_data":  StreamData(NewStreamDataSpec(mkID(1, 16), 0, Raw, cbor.Bytes(nil), nil)),
		"stream_end":   StreamEnd(NewStreamEndSpec(mkID(1, 16), Send, nil)),
		"stream_error": StreamErrorFrame(NewStreamErrorSpec(mkID(1, 16), "x", "y", nil)),
		"stream_reply": StreamReply(NewStreamReplySpec(mkID(1, 16), cbor.Null(), mkID(1, 32))),
	} {
		for _, field := range []string{"realm", "call_id", "source_route"} {
			fv, ok := v.Get(field)
			if !ok || !fv.IsNull() {
				t.Errorf("%s: field %q = %v, want Null", name, field, fv)
			}
		}
	}
}

func TestFrameStreamID(t *testing.T) {
	v := StreamEnd(NewStreamEndSpec(mkID(5, 16), Send, nil))
	id, ok := FrameStreamID(v)
	if !ok {
		t.Fatalf("FrameStreamID: not ok")
	}
	if !bytes.Equal(id, mkID(5, 16)) {
		t.Errorf("FrameStreamID mismatch")
	}
}

func TestStreamModeEncodingRoleNameRoundTrip(t *testing.T) {
	for _, m := range []StreamMode{ServerStream, ClientStream, Bidi} {
		got, ok := streamModeFromName(m.Name())
		if !ok || got != m {
			t.Errorf("StreamMode %v round trip failed via name %q", m, m.Name())
		}
	}
	for _, e := range []StreamEncoding{Raw, Msgpack} {
		got, ok := streamEncodingFromName(e.Name())
		if !ok || got != e {
			t.Errorf("StreamEncoding %v round trip failed via name %q", e, e.Name())
		}
	}
	for _, r := range []StreamRole{Send, Both} {
		got, ok := streamRoleFromName(r.Name())
		if !ok || got != r {
			t.Errorf("StreamRole %v round trip failed via name %q", r, r.Name())
		}
	}
}
