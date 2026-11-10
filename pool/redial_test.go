package pool

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// The schedule these tests watch. It is a test's own numbers, not macula's:
// short enough to see a retry or two, with a growth steep enough that the fifth
// failed retry parks the station for 20 seconds, far longer than any window
// these tests then wait in. A test that re-arms and one that does not are then
// seconds apart, so none of them can pass by winning a race.
func watched() func(*Opts) {
	return func(o *Opts) {
		o.Redial = Redial{Base: 2 * time.Millisecond, Factor: 10, Cap: time.Minute, SteadyUp: 10 * time.Second}
	}
}

// watches fills in a schedule a test chooses.
func watches(r Redial) func(*Opts) {
	return func(o *Opts) { o.Redial = r }
}

// steadyUpWatch is the schedule for the two steady-up tests: a window short
// enough to sit through, long enough to kill a link a third of the way in.
func steadyUpWatch() Redial {
	return Redial{Base: 20 * time.Millisecond, Factor: 2, Cap: 500 * time.Millisecond, SteadyUp: 300 * time.Millisecond}
}

// attemptsOf is how many backoff retries the pool has counted for the station,
// or -1 when it holds no member for it.
func attemptsOf(p *Pool, station [32]byte) int {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	for _, m := range members {
		if m.target.ExpectedNodeID != station {
			continue
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.attempts
	}
	return -1
}

// within waits up to d for ok, reporting what was never true.
func within(t *testing.T, d time.Duration, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("never within %s: %s", d, what)
}

// The wait before a retry grows by the factor per failed attempt, is never
// below the base and never above the cap, and is exactly the base on the first
// attempt: the floor has no range above it to spread within yet.
func TestTheRedialWaitGrowsFromTheBaseToTheCap(t *testing.T) {
	r, err := Redial{}.checked()
	if err != nil {
		t.Fatalf("the defaults are not a schedule: %v", err)
	}
	for range 100 {
		if got := r.wait(0); got != DefaultRedialBase {
			t.Fatalf("a first retry waits %s, want the base %s exactly", got, DefaultRedialBase)
		}
	}
	ceiling := DefaultRedialBase
	for attempt := range 20 {
		if attempt > 0 {
			ceiling = min(DefaultRedialCap, ceiling*time.Duration(DefaultRedialFactor))
		}
		for range 20 {
			got := r.wait(attempt)
			if got < DefaultRedialBase || got > ceiling {
				t.Fatalf("retry %d waits %s, outside the base %s to the ceiling %s", attempt, got, DefaultRedialBase, ceiling)
			}
		}
	}
	// The wait really does grow: a late retry reaches well past the base.
	if got := r.wait(6); got <= DefaultRedialBase*time.Duration(DefaultRedialFactor) {
		t.Errorf("a sixth retry waits %s, want it grown past twice the base", got)
	}
}

// A seed whose tier is not the active one retries on the schedule, and every
// failed retry is counted, which is what makes the wait grow; the active tier's
// link takes the flat respawn delay and counts nothing.
func TestATierThatIsDownEscalatesItsRedial(t *testing.T) {
	public := teststation.Start(t, profile.PQPure, "redial public")
	gone := teststation.Start(t, profile.PQPure, "redial fallback")
	// A station that refuses fails a dial at once, where a stopped one leaves
	// the dialer waiting out the QUIC handshake timeout.
	gone.Refuse(time.Minute)
	realm := teststation.NewRealm(t, profile.PQPure, "redial escalates", org)
	p := connectTieredWith(t, "redial escalates", realm, []*teststation.Station{public},
		[]*teststation.Station{gone}, watched())
	eventually(t, "the fallback seed's third backoff retry", func() bool { return attemptsOf(p, gone.NodeID) >= 3 })
	if got := attemptsOf(p, public.NodeID); got != 0 {
		t.Errorf("the active tier's link counted %d backoff retries, want 0", got)
	}
}

// A link that stays up past the steady-up window has proved itself: its
// station's backoff starts again from zero, so the next failure counts from one.
func TestALinkThatStaysUpResetsItsBackoff(t *testing.T) {
	public, lan, realm := tiers(t)
	p := connectTieredWith(t, "redial stays up", realm, []*teststation.Station{public}, []*teststation.Station{lan},
		watches(steadyUpWatch()))
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	lan.Drop(p.NodeID())
	eventually(t, "the fallback seed's first backoff retry", func() bool { return attemptsOf(p, lan.NodeID) == 1 })
	eventually(t, "the link that stayed up clearing it", func() bool { return attemptsOf(p, lan.NodeID) == 0 })
}

// The other half of that rule: a link that connects and dies before the window
// elapses resets nothing, so a connect-then-die loop keeps the backoff it
// accumulated instead of retrying at the base forever. The death is timed a
// third of the way into the window, well outside any reset that fired at the
// handshake, so a pool that reset on connect cannot pass by winning the race.
func TestALinkThatDiesEarlyKeepsIt(t *testing.T) {
	public, lan, realm := tiers(t)
	schedule := steadyUpWatch()
	p := connectTieredWith(t, "redial dies early", realm, []*teststation.Station{public}, []*teststation.Station{lan},
		watches(schedule))
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	lan.Drop(p.NodeID())
	eventually(t, "the first backoff retry", func() bool { return attemptsOf(p, lan.NodeID) == 1 })
	eventually(t, "the link back", func() bool { return lan.Connected(p.NodeID()) })
	time.Sleep(schedule.SteadyUp / 3)
	lan.Drop(p.NodeID())
	eventually(t, "the second backoff retry", func() bool { return attemptsOf(p, lan.NodeID) == 2 })
}

// A tier that becomes the active one does not inherit the wait the other tier
// earned: every pending retry of it restarts at the redial base with its count
// cleared, while the tier that just went keeps the wait it earned.
func TestAFallbackRetryRearmsWhenThePublicTierDies(t *testing.T) {
	public, lan, realm := tiers(t)
	p := connectTieredWith(t, "redial rearm", realm, []*teststation.Station{public}, []*teststation.Station{lan},
		watched())
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	lan.Refuse(time.Minute)
	lan.Drop(p.NodeID())
	eventually(t, "the fallback seed parked for twenty seconds", func() bool { return attemptsOf(p, lan.NodeID) >= 5 })
	lan.Allow()
	public.Stop()
	within(t, time.Second, "the fallback link up once its tier became the active one", func() bool {
		return p.ActiveTier() == TierFallback && lan.Connected(p.NodeID())
	})
	if got := attemptsOf(p, lan.NodeID); got != 0 {
		t.Errorf("the re-armed retry counted %d before it dialled, want 0", got)
	}
}

// And the other way: a public link that comes up makes the public tier active
// again, and the public seed waiting out a long retry is dialled on the base
// rather than left on the wait the outage earned. The link that returns here is
// one the pool dials for a call, which is a public link like any other.
func TestAPublicRetryRearmsWhenAPublicLinkReturns(t *testing.T) {
	serving := teststation.Start(t, profile.PQPure, "rearm serving")
	public, lan, realm := tiers(t)
	teststation.ShareDHT(serving, lan)
	realm.Admit(t, serving, nodeIDOf(t, "rearm provider"))
	provider := connect(t, "rearm provider", realm, serving)
	if _, err := provider.Serve(t.Context(), Offer{Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	public.Refuse(time.Minute)
	p := connectTieredWith(t, "rearm caller", realm, []*teststation.Station{public}, []*teststation.Station{lan},
		watched())
	eventually(t, "the pool on the fallback tier", func() bool { return p.ActiveTier() == TierFallback })
	eventually(t, "the public seed parked for twenty seconds", func() bool { return attemptsOf(p, public.NodeID) >= 5 })
	if _, err := p.Call(t.Context(), Call{Realm: realm.ID, Procedure: procedure, Payload: cbor.Text("hello")}); err != nil {
		t.Fatalf("Call: %v", err)
	}
	within(t, time.Second, "the public tier back", func() bool { return p.ActiveTier() == TierPublic })
	// Long enough that a flat retry of the still-refused station would have
	// failed and been counted; the active tier's flat delay counts nothing.
	time.Sleep(3 * p.opts.RespawnDelay)
	if got := attemptsOf(p, public.NodeID); got != 0 {
		t.Errorf("the re-armed retry counted %d on the flat delay, want 0", got)
	}
}
