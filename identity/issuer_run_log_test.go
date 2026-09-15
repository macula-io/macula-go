package identity

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// lockedLog is a log output that goroutines can write while a test reads it.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// RunEvery with no error handler logs a failed tick as a warning on slog's
// default logger, so a rotation that keeps failing is never swallowed.
func TestRunEveryWithoutAnErrorHandlerLogsAFailedTick(t *testing.T) {
	identity := sharedKey(t, pureIdentityKey)
	clock := newTestClock()
	issuer := newIssuer(t, identity, clock)
	logged := &lockedLog{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ticks := make(chan time.Time)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		issuer.RunEvery(ctx, ticks, nil)
		close(done)
	}()
	clock.set(maxProtocolInt - 1)
	ticks <- time.Now()
	cancel()
	<-done

	if line := logged.String(); !strings.Contains(line, "level=WARN") || !strings.Contains(line, "tick failed") {
		t.Fatalf("logged %q, want a warning that the tick failed", line)
	}
}
