package connection

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/frame"
)

// recordingHandler keeps each record's attributes as the SDK handed them to
// slog, before any handler quotes or escapes them.
type recordingHandler struct {
	mu      sync.Mutex
	records []map[string]string
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler            { return h }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := map[string]string{"msg": r.Message}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, attrs)
	return nil
}

// awaitMessage waits up to two seconds for a record logged with msg, and
// returns every record logged with it by then.
func (h *recordingHandler) awaitMessage(t *testing.T, msg string) []map[string]string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for len(h.withMessage(msg)) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return h.withMessage(msg)
}

// withMessage is every record logged with msg.
func (h *recordingHandler) withMessage(msg string) []map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out []map[string]string
	for _, r := range h.records {
		if r["msg"] == msg {
			out = append(out, r)
		}
	}
	return out
}

// A GOODBYE's reason and detail reach the session-end line each cut to 256
// bytes and with their control characters escaped, however long the station
// made them and whatever they hold, and the SDK's own words around them stay
// whole.
func TestASessionEndLineCutsAndEscapesTheGoodbyeReason(t *testing.T) {
	s, fc, _ := readingSession(t)
	recorded := &recordingHandler{}
	s.SetLogger(slog.New(recorded))
	reason := "shutdown\nforged=1" + strings.Repeat("r", 100_000)
	detail := "detail\x1b"
	fc.send(t, frame.Goodbye(reason, &detail))
	select {
	case <-s.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("the session did not end after the station's GOODBYE")
	}

	// The session reports its end before it writes the line, so wait for it.
	lines := recorded.awaitMessage(t, "macula: session ended")
	if len(lines) != 1 {
		t.Fatalf("session-end records = %d, want 1", len(lines))
	}
	got := lines[0]["reason"]
	// The reason is cut to 256 bytes, 17 of them "shutdown\nforged=1", before
	// it is escaped.
	wantReason := `shutdown\nforged=1` + strings.Repeat("r", 256-len("shutdown\nforged=1"))
	want := "connection: session ended: connection: the station said goodbye: " + wantReason + ` (detail\u{1b})`
	if got != want {
		t.Fatalf("session-end reason is %d bytes, ending %q; want %d bytes, ending %q",
			len(got), got[max(0, len(got)-40):], len(want), want[len(want)-40:])
	}
}
