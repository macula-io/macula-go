package pool

import (
	"sync"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
	"github.com/macula-io/macula-go/ucan"
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
//
// Growth is asserted on the draw's range rather than on one draw: a wait is
// base plus a uniform draw over [0, ceiling-base], so a single draw can land
// anywhere in it, and a test that reads one draw fails on its own about one run
// in sixty. With the draw held at either end the formula is exact, and the real
// draw is then checked only for the range every draw must be in.

// checkedDefaults is macula's schedule with its defaults filled in.
func checkedDefaults(t *testing.T) Redial {
	t.Helper()
	r, err := Redial{}.checked()
	if err != nil {
		t.Fatalf("the defaults are not a schedule: %v", err)
	}
	return r
}

// theCeiling is the highest wait retry number attempt may reach: the base grown
// by the factor per attempt, and never above the cap.
func theCeiling(attempt int) time.Duration {
	ceiling := DefaultRedialBase
	for range attempt {
		ceiling = min(DefaultRedialCap, ceiling*time.Duration(DefaultRedialFactor))
	}
	return ceiling
}

// drawsWith runs f with the schedule's draw answered by draw, the real draw put
// back afterwards, so a test can place a wait at either end of its range.
func drawsWith(t *testing.T, draw func(time.Duration) time.Duration, f func()) {
	t.Helper()
	real := randBelow
	randBelow = draw
	t.Cleanup(func() { randBelow = real })
	f()
}

// A first retry waits the base and draws nothing: the floor has no range above
// it to spread within yet.
func TestAFirstRetryWaitsTheBaseWithNoDraw(t *testing.T) {
	r := checkedDefaults(t)
	drawsWith(t, func(n time.Duration) time.Duration {
		t.Fatalf("a first retry drew from a range of %s it must not have", n)
		return 0
	}, func() {
		if got := r.wait(0); got != DefaultRedialBase {
			t.Fatalf("a first retry waits %s, want the base %s exactly", got, DefaultRedialBase)
		}
	})
}

// A draw at the bottom of its range waits exactly the base, whatever the
// attempt: no wait is ever below the floor.
func TestARetryAtTheBottomOfItsRangeWaitsTheBase(t *testing.T) {
	r := checkedDefaults(t)
	drawsWith(t, func(time.Duration) time.Duration { return 0 }, func() {
		for attempt := range 20 {
			if got := r.wait(attempt); got != DefaultRedialBase {
				t.Fatalf("retry %d at the bottom of its range waits %s, want the base %s", attempt, got, DefaultRedialBase)
			}
		}
	})
}

// A draw at the top of its range waits the ceiling, which grows by the factor
// per attempt until it reaches the cap and stays there.
func TestARetryAtTheTopOfItsRangeWaitsTheGrownCeiling(t *testing.T) {
	r := checkedDefaults(t)
	drawsWith(t, func(n time.Duration) time.Duration { return n - 1 }, func() {
		for attempt := range 20 {
			ceiling := theCeiling(attempt)
			if got := r.wait(attempt); got != ceiling {
				t.Fatalf("retry %d at the top of its range waits %s, want the ceiling %s", attempt, got, ceiling)
			}
		}
		if got := theCeiling(19); got != DefaultRedialCap {
			t.Fatalf("twenty attempts reach a ceiling of %s, want the cap %s", got, DefaultRedialCap)
		}
	})
}

// Every draw the schedule really makes lands inside its attempt's range.
func TestARetryNeverWaitsOutsideItsAttemptsRange(t *testing.T) {
	r := checkedDefaults(t)
	for attempt := range 20 {
		ceiling := theCeiling(attempt)
		for range 20 {
			got := r.wait(attempt)
			if got < DefaultRedialBase || got > ceiling {
				t.Fatalf("retry %d waits %s, outside the base %s to the ceiling %s", attempt, got, DefaultRedialBase, ceiling)
			}
		}
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

// A re-arm can land in the window pause keeps between reading the count and
// counting the retry: the tier switches to this member's while its next wait is
// already planned (macula#201 §3, macula-go#82). The count the re-arm cleared
// must not be counted back, or the retry after the one it woke waits one step
// further along the schedule than the floor the re-arm promised.
//
// Every wait is placed at the top of its range, so the retry after the re-armed
// one plans the grown ceiling when it counted one and the base exactly when it
// did not: no draw can decide the test.
func TestAReArmInsideThePauseWindowLeavesNoCount(t *testing.T) {
	public, lan, realm := tiers(t)
	drawsWith(t, func(n time.Duration) time.Duration { return n - 1 }, func() {
		var mu sync.Mutex
		var plans []time.Duration
		rearmAt := -1
		beforePauseCount = func(m *member, wait time.Duration) {
			if m.target.ExpectedNodeID != lan.NodeID {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			plans = append(plans, wait)
			if rearmAt >= 0 {
				return
			}
			rearmAt = len(plans) - 1
			// The window itself: parked, the wait planned, the count not yet
			// taken. This is a tier switch landing here.
			m.rearm()
		}
		t.Cleanup(func() { beforePauseCount = nil })
		p := connectTieredWith(t, "rearm window", realm, []*teststation.Station{public},
			[]*teststation.Station{lan}, watched())
		eventually(t, "both links up", func() bool { return upCount(p) == 2 })
		lan.Refuse(time.Minute)
		lan.Drop(p.NodeID())
		eventually(t, "the retry after the re-armed one", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return rearmAt >= 0 && len(plans) > rearmAt+1
		})
		mu.Lock()
		after := plans[rearmAt+1]
		mu.Unlock()
		if after != p.opts.Redial.Base {
			t.Errorf("the retry after a re-arm in the pause window plans %s, want the redial base %s exactly",
				after, p.opts.Redial.Base)
		}
	})
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
	if _, err := provider.Serve(t.Context(), Offer{Policy: ucan.Open{}, Realm: realm.ID, Procedure: procedure, Handler: echo}); err != nil {
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
