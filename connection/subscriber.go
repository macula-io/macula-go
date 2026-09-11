package connection

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// EventHandler processes one inbound EVENT. Returning a non-nil error stops
// RunSubscriber and is returned to its caller — the Go equivalent of
// macula_subscriber.erl's handle_event/4 returning {stop, Reason, State}
// (Go threads any state the handler needs via closure instead of an
// explicit State argument passed back in).
type EventHandler func(frame.EventInfo) error

// subscriberPollInterval bounds how long a single Recv wait blocks between
// checking ctx — not a wire timeout, just how promptly a cancelled ctx is
// noticed when nothing is arriving.
const subscriberPollInterval = 2 * time.Second

// RunSubscriber is the supervised counterpart to Subscribe, matching
// macula_subscriber.erl's gen_server wrapper in spirit: it subscribes once,
// then hands every event for spec to handler for as long as this runs. Go has
// no OTP pid to address a running subscriber by; ctx cancellation plays that
// role — run this in its own goroutine and cancel ctx to stop it. The
// subscription is closed on return, including on cancellation.
//
// Blocks the calling goroutine until ctx is done, handler returns a non-nil
// error (returned here unchanged), or the subscription ends (returned
// wrapped).
func (s *Session) RunSubscriber(ctx context.Context, spec frame.SubscribeSpec, id identity.KeyPair, handler EventHandler) error {
	sub, err := s.Subscribe(spec, id)
	if err != nil {
		return err
	}
	defer func() { _ = sub.Close() }()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		evt, err := sub.Recv(subscriberPollInterval)
		if errors.Is(err, ErrRecvTimeout) {
			continue
		}
		if err != nil {
			return fmt.Errorf("connection: recv event: %w", err)
		}
		if err := handler(evt); err != nil {
			return err
		}
	}
}
