package connection

import (
	"context"
	"time"

	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
)

// KeepAdvertised sends an ADVERTISE for spec immediately, then again every
// interval, until ctx is done. Advertise's own doc notes the station's
// registration is tied to the connection that sent it — a long-lived
// server needs to keep re-asserting it. Advertise is a stateless,
// side-effect-free-on-repeat wire send (unlike the Erlang reference's
// advertise/5, which spawns a real per-call OTP supervisor and so needs a
// reuse_sup option to avoid leaking one per tick), so there is nothing
// equivalent to worry about leaking here.
//
// A failed tick is reported via onError (nil is fine) but does not stop
// the loop — it tries again at the next interval regardless. This cannot
// detect or repair a dead session on its own; if the underlying connection
// has actually gone down, every tick will keep failing until ctx is
// cancelled. See directdial.KeepAdvertisedDirect for the direct-dial
// equivalent (same shape, same reasoning).
func (s *Session) KeepAdvertised(ctx context.Context, spec frame.AdvertiseSpec, id identity.KeyPair, interval time.Duration, onError func(error)) {
	tick := func() {
		if err := s.Advertise(spec, id); err != nil && onError != nil {
			onError(err)
		}
	}
	tick()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
