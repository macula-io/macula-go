package connection

import (
	"crypto/rand"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// dropIntervals stands in for the timers a session's drop warnings start, so
// a test ends the intervals when it chooses.
type dropIntervals struct {
	mu      sync.Mutex
	lengths []time.Duration
	ends    []func()
}

func captureDropIntervals(s *Session) *dropIntervals {
	d := &dropIntervals{}
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	s.rt.afterDropInterval = func(length time.Duration, end func()) {
		d.mu.Lock()
		defer d.mu.Unlock()
		d.lengths = append(d.lengths, length)
		d.ends = append(d.ends, end)
	}
	return d
}

// started returns the length of every interval started so far.
func (d *dropIntervals) started() []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Duration(nil), d.lengths...)
}

// endAll ends every interval started and not yet ended.
func (d *dropIntervals) endAll() {
	d.mu.Lock()
	ends := d.ends
	d.ends = nil
	d.mu.Unlock()
	for _, end := range ends {
		end()
	}
}

// droppableCall is a CALL for procedure naming caller, signed by signer, or
// unsigned when signer is nil.
func droppableCall(t *testing.T, caller identity.KeyPair, signer *identity.KeyPair, procedure string) cbor.Value {
	t.Helper()
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		t.Fatalf("rand: %v", err)
	}
	call := frame.Call(frame.NewCallSpec(callID, procedure, testRealm(), cbor.Null(), time.Now().Add(time.Minute).UnixMilli(), caller.NodeID()))
	if signer == nil {
		return call
	}
	return frame.Sign(call, *signer)
}

// withField is v with field set to value, replacing any value it had.
func withField(v cbor.Value, field string, value cbor.Value) cbor.Value {
	kept, _ := withoutField(v, field).AsMap()
	return cbor.Map(append(kept, cbor.MapEntry{Key: cbor.Text(field), Val: value}))
}

// withoutField is v without field.
func withoutField(v cbor.Value, field string) cbor.Value {
	entries, _ := v.AsMap()
	kept := make([]cbor.MapEntry, 0, len(entries))
	for _, e := range entries {
		if key, _ := e.Key.AsText(); key != field {
			kept = append(kept, e)
		}
	}
	return cbor.Map(kept)
}

func dropWarnings(logged *lockedBuffer) []string {
	return linesWith(logged.String(), "macula: drop warning")
}

// hasFields reports whether a log line carries every one of fields whole.
func hasFields(line string, fields ...string) bool {
	for _, f := range fields {
		if !strings.Contains(line+" ", " "+f+" ") {
			return false
		}
	}
	return true
}

// A burst of drops of one kind logs the first at once and the rest in one
// closing line when the interval ends, with the most recent drop's reason
// and its procedure cut to 256 bytes without splitting a character. The next
// drop after that opens a new interval and is logged at once.
func TestADropBurstLogsOneImmediateLineAndOneClosingLineWithTheRest(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	s.SetDropWarningInterval(42 * time.Second)
	intervals := captureDropIntervals(s)
	caller, other := registryIdentity(t), registryIdentity(t)

	fc.send(t, droppableCall(t, caller, &other, "first.procedure"))
	fc.send(t, droppableCall(t, caller, &other, "second.procedure"))
	fc.send(t, droppableCall(t, caller, nil, strings.Repeat("p", 255)+"é"))
	roundTrip(t, s, fc, id)

	lines := dropWarnings(logged)
	if len(lines) != 1 || !hasFields(lines[0], "kind=dropped_call", "count=1", "reason=invalid_signature", "procedure=first.procedure") {
		t.Fatalf("drop warnings during the burst = %q, want one line, for the first drop", lines)
	}
	if started := intervals.started(); len(started) != 1 || started[0] != 42*time.Second {
		t.Fatalf("intervals started = %v, want one of the 42s set", started)
	}

	intervals.endAll()
	lines = dropWarnings(logged)
	if len(lines) != 2 || !hasFields(lines[1], "kind=dropped_call", "count=2", "reason=unsigned", "procedure="+strings.Repeat("p", 255)) {
		t.Fatalf("drop warnings after the interval = %q, want a closing line counting the other two, with the last one's reason and its procedure cut before the character that would split", lines)
	}

	fc.send(t, droppableCall(t, caller, &other, "after.the.interval"))
	roundTrip(t, s, fc, id)
	if lines = dropWarnings(logged); len(lines) != 3 || !hasFields(lines[2], "count=1", "procedure=after.the.interval") {
		t.Fatalf("drop warnings after a drop in a new interval = %q, want it logged at once", lines)
	}
}

// A drop with no other of its kind in its interval logs only the immediate
// line: the interval, a minute unless set, ends without a closing line.
func TestASingleDropLogsOnlyTheImmediateLine(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	intervals := captureDropIntervals(s)
	caller, other := registryIdentity(t), registryIdentity(t)

	fc.send(t, droppableCall(t, caller, &other, "only.procedure"))
	roundTrip(t, s, fc, id)
	intervals.endAll()

	if lines := dropWarnings(logged); len(lines) != 1 || !hasFields(lines[0], "kind=dropped_call", "count=1", "reason=invalid_signature", "procedure=only.procedure") {
		t.Fatalf("drop warnings = %q, want only the immediate line", lines)
	}
	if started := intervals.started(); len(started) != 1 || started[0] != time.Minute {
		t.Fatalf("intervals started = %v, want one of the default minute", started)
	}
}

// An inbound CALL is dropped for the first thing wrong with it: no signature
// or no caller, then a signature that doesn't verify against the caller,
// then a field missing or of the wrong type.
func TestAnInboundCallIsDroppedForTheFirstThingWrongWithIt(t *testing.T) {
	caller, other := registryIdentity(t), registryIdentity(t)
	call := droppableCall(t, caller, nil, "p")
	cases := []struct {
		name  string
		frame cbor.Value
		want  dropReason
	}{
		{"signed by its caller", frame.Sign(call, caller), ""},
		{"no signature", call, reasonUnsigned},
		{"no caller", frame.Sign(withoutField(call, "caller"), caller), reasonUnsigned},
		{"signed by another", frame.Sign(call, other), reasonInvalidSignature},
		{"a caller that isn't a key", frame.Sign(withField(call, "caller", cbor.Text("me")), caller), reasonInvalidSignature},
		{"no deadline", frame.Sign(withoutField(call, "deadline_ms"), caller), reasonMalformed},
	}
	for _, tc := range cases {
		if _, got := verifiedCall(tc.frame); got != tc.want {
			t.Errorf("%s: dropped for %q, want %q", tc.name, got, tc.want)
		}
	}
}

// A RESULT that doesn't parse or that nothing waits for is counted as
// unrouted and warned about as a dropped reply carrying its call_id's first
// 4 bytes, not with the unrouted-frame line.
func TestAReplyNothingWaitsForIsWarnedAboutAsADroppedReply(t *testing.T) {
	s, fc, id := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	intervals := captureDropIntervals(s)
	unknown := append([]byte{0xde, 0xad, 0xbe, 0xef}, make([]byte, 12)...)
	result := frame.Result(frame.NewResultSpec(unknown, cbor.Null(), stationNode(9)))

	fc.send(t, result)
	fc.send(t, withoutField(result, "payload"))
	roundTrip(t, s, fc, id)
	intervals.endAll()

	lines := dropWarnings(logged)
	if len(lines) != 2 ||
		!hasFields(lines[0], "kind=dropped_reply", "count=1", "reason=unknown_call_id", "call_id=deadbeef") ||
		!hasFields(lines[1], "kind=dropped_reply", "count=1", "reason=malformed", "call_id=deadbeef") {
		t.Fatalf("drop warnings = %q, want the unknown call_id at once and the malformed reply in the closing line", lines)
	}
	if n := s.Unrouted()["result"]; n != 2 {
		t.Fatalf("unrouted results = %d, want both counted", n)
	}
	if unrouted := linesWith(logged.String(), "unrouted result"); len(unrouted) != 0 {
		t.Fatalf("unrouted-frame lines for results = %q, want none", unrouted)
	}
}
