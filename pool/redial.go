package pool

import (
	"fmt"
	"math/rand/v2"
	"time"
)

// Macula's redial schedule (macula#201 §3): a station whose tier is not the
// active one is dialed again on the base, growing by the factor on each failed
// retry up to the cap, with the wait spread randomly above the base; a link
// that stays up the steady-up window has proved itself and its station's count
// starts again from zero.
const (
	DefaultRedialBase     = 5 * time.Second
	DefaultRedialFactor   = 2
	DefaultRedialCap      = 5 * time.Minute
	DefaultRedialSteadyUp = time.Minute
)

// Redial is the schedule a pool dials a station again on while its tier is not
// the active one. Zero fields take macula's defaults.
type Redial struct {
	// Base is the floor, and the exact wait of a first retry.
	Base time.Duration
	// Factor multiplies the wait per failed retry, up to Cap.
	Factor int
	// Cap is the longest wait the schedule reaches.
	Cap time.Duration
	// SteadyUp is how long a link must stay up to clear its station's count.
	SteadyUp time.Duration
}

// withDefaults fills the zero fields with macula's.
func (r Redial) withDefaults() Redial {
	r.Base = orDuration(r.Base, DefaultRedialBase)
	r.Factor = orDefault(r.Factor, DefaultRedialFactor)
	r.Cap = orDuration(r.Cap, DefaultRedialCap)
	r.SteadyUp = orDuration(r.SteadyUp, DefaultRedialSteadyUp)
	return r
}

// checked fills the defaults in and refuses a schedule that cannot be one.
func (r Redial) checked() (Redial, error) {
	r = r.withDefaults()
	if r.Base <= 0 || r.Factor < 1 || r.Cap <= 0 || r.SteadyUp <= 0 {
		return r, fmt.Errorf("%w: redial base %s, factor %d, cap %s, steady up %s",
			ErrInvalidOpts, r.Base, r.Factor, r.Cap, r.SteadyUp)
	}
	return r, nil
}

// randBelow is the uniform draw a wait spreads over its range above the floor.
// It is a variable only so that a test can place a draw at either end of that
// range instead of waiting for one; wait is its only caller.
var randBelow = func(n time.Duration) time.Duration { return rand.N(n) }

// wait is the wait before a failed retry number attempt is made again
// (macula#201 §3):
//
//	base + random(0, min(cap, base*factor^attempt) - base)
//
// The floor is exact: attempt 0 waits exactly the base, with no jitter at all,
// because there is no range above the floor to spread within yet. No wait is
// below the base, and none above the cap.
func (r Redial) wait(attempt int) time.Duration {
	ceiling := min(r.Cap, r.grown(attempt))
	if ceiling <= r.Base {
		return r.Base
	}
	return r.Base + randBelow(ceiling-r.Base+1)
}

// grown is base*factor^attempt, stopping as soon as it reaches the cap: a value
// above the cap is never used, and an attempt count nobody bounded must not
// build a number only to throw it away.
func (r Redial) grown(attempt int) time.Duration {
	grown := r.Base
	for range attempt {
		next := grown * time.Duration(r.Factor)
		if next < grown || next >= r.Cap {
			return r.Cap
		}
		grown = next
	}
	return grown
}

// respawnPlan is the wait before this member's next dial, and whether it is a
// backoff retry that counts against the member: the flat respawn delay while
// its tier is the active one — which is not a backoff and leaves the count
// alone, so a single link flapping inside a healthy tier never escalates
// anyone's wait — and the schedule while it is not.
//
// The plan is made once the ended link has left the pool's state, so a tier
// that has just lost its last link is already not active, and its retries take
// the schedule instead of one dial a second.
func (p *Pool) respawnPlan(tier Tier, attempt int) (time.Duration, bool) {
	if p.ActiveTier() == tier {
		return p.opts.RespawnDelay, false
	}
	return p.opts.Redial.wait(attempt), true
}

// noticeTier re-arms the pool's pending retries when the tier the pool is on
// has changed (macula#201 §3): every parked retry of the tier that has just
// become the active one starts again from the redial base, its count cleared,
// and a retry of the tier that just went keeps the wait it earned — that
// backoff is what makes a long outage cheap.
func (p *Pool) noticeTier(before Tier) {
	active := p.ActiveTier()
	if active == before {
		return
	}
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	p.mu.Unlock()
	for _, m := range members {
		if m.tier == active {
			m.rearm()
		}
	}
}

func orDuration(v, fallback time.Duration) time.Duration {
	if v == 0 {
		return fallback
	}
	return v
}
