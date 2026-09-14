package pool

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

// A pool link warns about the frames its session drops, as a session
// connected on its own does: every session a link dials, a redial's included,
// is given the pool's Logger and DropWarningInterval.
func TestEveryLinkSessionIsGivenThePoolsLoggerAndDropWarningInterval(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	first, redialed, other := newFakeSession(), newFakeSession(), newFakeSession()
	dialer.script("a.example", 4433, first, redialed)
	dialer.script("b.example", 4433, other)
	opts := testOpts(id, dialer.dial)
	opts.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	opts.DropWarningInterval = 7 * time.Second

	p, err := Connect(context.Background(), []Seed{{Host: "a.example", Port: 4433}, {Host: "b.example", Port: 4433}}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()

	assertGivenLogging(t, "the first session", first, opts)
	assertGivenLogging(t, "the other link's session", other, opts)
	first.kill()
	assertGivenLogging(t, "the redialed session", redialed, opts)
}

// assertGivenLogging checks that s is given opts' logger and drop warning
// interval within two seconds.
func assertGivenLogging(t *testing.T, name string, s *fakeSession, opts Opts) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	logger, interval := s.logging()
	for (logger == nil || interval == 0) && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		logger, interval = s.logging()
	}
	if logger != opts.Logger || interval != opts.DropWarningInterval {
		t.Errorf("%s was given logger %p and drop warning interval %v, want the pool's %p and %v",
			name, logger, interval, opts.Logger, opts.DropWarningInterval)
	}
}
