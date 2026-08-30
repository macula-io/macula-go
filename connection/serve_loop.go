package connection

import (
	"context"
	"errors"
	"time"

	"github.com/macula-io/macula-go-sdk/identity"
)

// servePollInterval bounds how long a single ServeOneCallGated tick
// blocks between checking ctx — not a wire timeout, mirrors
// subscriberPollInterval's own reasoning exactly.
const servePollInterval = 2 * time.Second

// ServeForever answers inbound CALLs against lookup/policy for as long
// as ctx is not done, instead of returning after exactly one — the
// provider-role counterpart to RunSubscriber, and what a daemon-style
// long-lived server needs instead of hand-rolling
//
//	for { session.ServeOneCallGated(lookup, policy, id, timeout) }
//
// itself: lookup and policy are plain functions, so a caller wanting to
// register or unregister procedures while this runs does so by mutating
// whatever state they close over (e.g. a mutex-guarded map) — this loop
// doesn't need its own registration API to support that.
//
// Blocks the calling goroutine until ctx is done (returned as ctx.Err())
// or the control stream fails with something other than a per-tick
// timeout (returned wrapped, same as ServeOneCallGated's own non-timeout
// errors). A handler error or an unauthorized/unknown-procedure refusal
// is answered on the wire and does NOT stop the loop, matching
// ServeOneCallGated's own single-call contract: those are successful
// sends of an ERROR frame, not loop-ending failures.
func (s *Session) ServeForever(ctx context.Context, lookup CallLookup, policy PolicyLookup, id identity.KeyPair) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		err := s.ServeOneCallGated(lookup, policy, id, servePollInterval)
		if err != nil && !errors.Is(err, ErrServeOneCallTimeout) {
			return err
		}
	}
}
