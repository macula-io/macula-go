package pool

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Resolve is the schedule a pool asks the DHT again on while a round sent
// nothing: the pause doubles from the base up to the cap, macula's own values
// (macula_direct_dial.erl:56-59, "after a pause that doubles from 100 ms to at
// most 1 s"). A zero Resolve takes them.
type Resolve struct {
	// Base is the pause after the first round that sent nothing.
	Base time.Duration
	// Factor multiplies the pause per round, up to Cap.
	Factor int
	// Cap is the longest pause the schedule reaches.
	Cap time.Duration
}

const (
	// DefaultResolveBase and DefaultResolveCap are the ends of macula's pause
	// schedule (macula_direct_dial.erl:56-59).
	DefaultResolveBase   = 100 * time.Millisecond
	DefaultResolveCap    = time.Second
	DefaultResolveFactor = 2

	// DefaultDialTimeout is macula's ?DEFAULT_DIAL_TIMEOUT_MS
	// (macula_direct_dial.erl:184, used at :404 and :1058): the window a
	// stream's resolve-and-reach phase gets, from the same define, not a
	// second number of our own.
	DefaultDialTimeout = 10 * time.Second
)

// withDefaults fills the zero fields with macula's.
func (r Resolve) withDefaults() Resolve {
	r.Base = orDuration(r.Base, DefaultResolveBase)
	r.Factor = orDefault(r.Factor, DefaultResolveFactor)
	r.Cap = orDuration(r.Cap, DefaultResolveCap)
	return r
}

// checked fills the defaults in and refuses a schedule that cannot be one.
func (r Resolve) checked() (Resolve, error) {
	r = r.withDefaults()
	if r.Base <= 0 || r.Factor < 1 || r.Cap < r.Base {
		return r, fmt.Errorf("%w: resolve base %s, factor %d, cap %s", ErrInvalidOpts, r.Base, r.Factor, r.Cap)
	}
	return r, nil
}

// next is the pause after attempt rounds that sent nothing, never past the cap.
func (r Resolve) next(pause time.Duration) time.Duration {
	return min(pause*time.Duration(r.Factor), r.Cap)
}

// pauseFor is the wait between two rounds, ending early when ctx ends. It is a
// variable only so that a test can record the schedule instead of waiting it
// out, as randBelow is for the redial schedule; reask is its only caller.
var pauseFor = func(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// errCandidateUnchanged is a candidate the walk passes over without dialling it
// again: its advertisement and its station_endpoint record are the ones the last
// attempt already failed against (macula_direct_dial.erl:56-59).
var errCandidateUnchanged = errors.New("pool: the candidate has not changed since the last attempt")

// candidateID names one candidate across a call's rounds.
type candidateID struct {
	provider [32]byte
	station  [32]byte
}

func idOf(cand candidate) candidateID {
	return candidateID{provider: cand.Node, station: cand.Station}
}

// endpointID is the station_endpoint record an attempt read: the record's
// createdAt, or why there was none. read is false when the attempt found a link
// up already and read no record at all.
type endpointID struct {
	read      bool
	createdAt int64
	reason    string
}

// attempt is what one candidate looked like when it last failed before
// anything was sent to it.
type attempt struct {
	advertised int64
	endpoint   endpointID
}

// unchanged reports whether cand is the candidate the last attempt passed over:
// the same advertisement and the same station_endpoint record.
func (a attempt) unchanged(advertised int64, endpoint endpointID) bool {
	return a.advertised == advertised && a.endpoint == endpoint
}

// conclusion holds what a call's rounds have found so far, in macula's order
// (macula_direct_dial.erl:61-67): the candidates that were reached and failed,
// whether the latest answered lookup found nothing, and the latest lookup that
// failed.
type conclusion struct {
	failed []error
	empty  bool
	lookup error
}

// error is the call's outcome when it can ask no more. A cancel is reported as
// the cancel it is; otherwise macula's order decides, and a lookup that failed
// is joined with the call's own deadline so that a binding reads it the same
// way whether or not the ABI handed the call a timeout.
func (c conclusion) error(ctx context.Context) error {
	err := ctx.Err()
	if err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	deadline := err
	if deadline == nil {
		// The deadline is spent even if the context's own timer has not fired.
		deadline = context.DeadlineExceeded
	}
	switch {
	case len(c.failed) > 0:
		return errors.Join(append([]error{ErrNoProvider}, c.failed...)...)
	case c.empty:
		return ErrNoProvider
	case c.lookup != nil:
		return errors.Join(c.lookup, deadline)
	}
	return deadline
}

// walkResult is one round's walk: the answer when something was sent, why the
// walk stopped when it was not merely out of candidates, and the candidates
// that were reached and failed before anything was sent.
type walkResult[T any] struct {
	out     T
	sent    bool
	outcome error
	failed  []error
	stop    error
}

// reask asks the DHT again after every round that sent nothing, until something
// is sent or the call ends: a record published too recently to be readable at
// the caller's station is not a miss until the deadline (macula-go#76, as
// macula_direct_dial.erl:56-67).
func reask[T any](p *Pool, ctx context.Context, ask func(context.Context) ([]candidate, error),
	walk func(context.Context, []candidate) walkResult[T]) (T, error) {
	var zero T
	var last conclusion
	pause := p.opts.Resolve.Base
	for {
		out, sent, err := round(ctx, ask, walk, &last)
		if sent || err != nil {
			return out, err
		}
		if p.isClosed() {
			return zero, errors.Join(ErrClosed, ctx.Err())
		}
		left := time.Until(deadlineOf(ctx))
		if left <= 0 {
			return zero, last.error(ctx)
		}
		pauseFor(ctx, min(pause, left))
		pause = p.opts.Resolve.next(pause)
	}
}

// round is one ask of the DHT and one walk of what it found, folding what they
// leave behind into last: the answer when something was sent, and otherwise
// why to stop when the round cannot carry on.
func round[T any](ctx context.Context, ask func(context.Context) ([]candidate, error),
	walk func(context.Context, []candidate) walkResult[T], last *conclusion) (T, bool, error) {
	var zero T
	if ctx.Err() != nil {
		return zero, false, last.error(ctx)
	}
	cands, err := ask(ctx)
	switch {
	case err != nil:
		// A lookup the deadline cut off records nothing (macula).
		if ctx.Err() != nil {
			return zero, false, last.error(ctx)
		}
		last.lookup, last.empty = err, false
		return zero, false, nil
	case len(cands) == 0:
		last.lookup, last.empty = nil, true
		return zero, false, nil
	}
	result := walk(ctx, cands)
	if result.sent {
		return result.out, true, result.outcome
	}
	if result.stop != nil {
		return zero, false, result.stop
	}
	if len(result.failed) > 0 {
		last.failed, last.empty = result.failed, false
	}
	return zero, false, nil
}
