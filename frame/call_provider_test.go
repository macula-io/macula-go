package frame

import (
	"bytes"
	"testing"

	"github.com/macula-io/macula-go/cbor"
)

func TestParseCallRoundTrips(t *testing.T) {
	spec := NewCallSpec(mkID(1, 16), "math.add", mkID(2, 32), cbor.Text("payload"), 12345, mkID(3, 32))
	v := Call(spec)

	info, err := ParseCall(v)
	if err != nil {
		t.Fatalf("ParseCall: %v", err)
	}
	if !bytes.Equal(info.CallID, spec.CallID) {
		t.Errorf("CallID mismatch")
	}
	if info.Procedure != spec.Procedure {
		t.Errorf("Procedure = %q, want %q", info.Procedure, spec.Procedure)
	}
	if !bytes.Equal(info.Realm, spec.Realm) {
		t.Errorf("Realm mismatch")
	}
	if txt, ok := info.Payload.AsText(); !ok || txt != "payload" {
		t.Errorf("Payload = %v, want Text(payload)", info.Payload)
	}
	if info.DeadlineMs != 12345 {
		t.Errorf("DeadlineMs = %d, want 12345", info.DeadlineMs)
	}
	if !bytes.Equal(info.Caller, spec.Caller) {
		t.Errorf("Caller mismatch")
	}
}

func TestParseCallRejectsWrongFrameType(t *testing.T) {
	other := Goodbye("bye", nil)
	if _, err := ParseCall(other); err != ErrNotACallFrame {
		t.Errorf("ParseCall(non-call) = %v, want ErrNotACallFrame", err)
	}
}

func TestParseCallRejectsAResultFrame(t *testing.T) {
	// A CALL's own responses (RESULT/ERROR) must not be mistaken for
	// inbound CALLs by a provider's dispatch loop.
	result := Result(NewResultSpec(mkID(1, 16), cbor.Text("ok"), mkID(2, 32)))
	if _, err := ParseCall(result); err != ErrNotACallFrame {
		t.Errorf("ParseCall(result) = %v, want ErrNotACallFrame", err)
	}
}
