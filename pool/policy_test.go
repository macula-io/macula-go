package pool

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
)

// loggedLines collects what slog's default logger writes, which is where an
// operator sees the pool: a serve is logged, so the test reads the same line.
type loggedLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *loggedLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *loggedLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func (l *loggedLines) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.buf.Reset()
}

// echoStream is a stream handler that answers nothing: these tests are about
// whether the procedure is served at all.
func echoStream(_ context.Context, s *stationlink.Stream) error { return s.Close() }

// A pool serves a procedure to any caller only when the offer says so, unary
// and streaming alike (macula-go#57, #60): an offer with no policy is refused
// before a realm key is resolved or a link dialed, so the station never
// advertises it.
func TestAServeWithNoPolicyIsRefused(t *testing.T) {
	for _, c := range []struct {
		name   string
		stream bool
	}{
		{"unary", false},
		{"stream", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := teststation.Start(t, profile.PQPure, "no policy "+c.name)
			realm := teststation.NewRealm(t, profile.PQPure, "no policy "+c.name, org)
			p := connect(t, "no policy "+c.name+" provider", realm, s)
			// An own-namespace procedure: nothing but the policy can refuse it,
			// so a serve that succeeds today is the hole itself.
			own := record.OwnProcedure(p.NodeID(), "echo")
			if _, err := p.Serve(t.Context(), unpolicied(realm.ID, own, c.stream)); !errors.Is(err, ErrPolicyRequired) {
				t.Fatalf("Serve with no policy: %v, want ErrPolicyRequired", err)
			}
			if s.Advertised(realm.ID, own) {
				t.Error("the station advertises a procedure the pool refused to serve")
			}
			assertPolicyBeforeAnyRealmKey(t, p, c.name, c.stream)
		})
	}
}

// unpolicied is an offer of one procedure that names no policy at all.
func unpolicied(realm [32]byte, procedure string, stream bool) Offer {
	if stream {
		return Offer{Realm: realm, Procedure: procedure,
			Stream: &stationlink.StreamOffer{Mode: frame.ServerStream, Handler: echoStream}}
	}
	return Offer{Realm: realm, Procedure: procedure, Handler: echo}
}

// assertPolicyBeforeAnyRealmKey checks the refusal is the pool's own and comes
// first: an org procedure in a realm this pool pins no key for is still refused
// for the policy it names, not for the key.
func assertPolicyBeforeAnyRealmKey(t *testing.T, p *Pool, name string, stream bool) {
	t.Helper()
	elsewhere := teststation.NewRealm(t, profile.PQPure, "unpinned "+name, org)
	_, err := p.Serve(t.Context(), unpolicied(elsewhere.ID, org+"/echo", stream))
	if !errors.Is(err, ErrPolicyRequired) {
		t.Errorf("Serve with no policy in an unpinned realm: %v, want ErrPolicyRequired before any realm key", err)
	}
}

// A pool serving an open procedure says so once, in macula's words, and says
// nothing for a gated one (macula-go#57, #60): the line is how an operator
// sees an app that opted out of gating, so it is written where the offer is
// accepted and nowhere else.
func TestAnOpenServeIsLoggedOnceAndAGatedOneIsNot(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "open log")
	realm := teststation.NewRealm(t, profile.PQPure, "open log", org)
	p := connect(t, "open log provider", realm, s)
	logged := &loggedLines{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logged, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	open := record.OwnProcedure(p.NodeID(), "open")
	servedOpen, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: open, Handler: echo, Policy: ucan.Open{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servedOpen.Stop() })
	lines := logged.String()
	if !strings.Contains(lines, "open callers") || !strings.Contains(lines, open) {
		t.Fatalf("serving open logged %q, want the opt-out line naming %s", lines, open)
	}
	if n := strings.Count(lines, "open callers"); n != 1 {
		t.Errorf("serving open logged the opt-out %d times, want once: %q", n, lines)
	}

	logged.Reset()
	gated := record.OwnProcedure(p.NodeID(), "gated")
	servedGated, err := p.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: gated, Handler: echo,
		Policy: ucan.UCANRequired{Issuer: p.NodeID()}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = servedGated.Stop() })
	if lines := logged.String(); lines != "" {
		t.Fatalf("serving gated logged %q, want nothing", lines)
	}
}
