package connection

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
)

// EventHandler processes one inbound EVENT. Returning a non-nil error stops
// RunSubscriber and is returned to its caller — the Go equivalent of
// macula_subscriber.erl's handle_event/4 returning {stop, Reason, State}
// (Go threads any state the handler needs via closure instead of an
// explicit State argument passed back in).
type EventHandler func(frame.EventInfo) error

// subscriberPollInterval bounds how long a single RecvEvent wait blocks
// between checking ctx — not a wire timeout, just how promptly a cancelled
// ctx is noticed when nothing is arriving.
const subscriberPollInterval = 2 * time.Second

// RunSubscriber is the supervised counterpart to the bare
// Subscribe/RecvEvent primitives, matching macula_subscriber.erl's
// gen_server wrapper in spirit: it subscribes once, then dispatches every
// inbound EVENT to handler for as long as this runs, instead of requiring
// the caller to hand-roll a RecvEvent poll loop. Go has no OTP pid to
// address a running subscriber by; ctx cancellation plays that role — run
// this in its own goroutine and cancel ctx to stop it (the equivalent of
// macula_subscriber's implicit "stop the gen_server" via its supervisor).
// Unsubscribes on return, including on cancellation.
//
// Blocks the calling goroutine until ctx is done, handler returns a
// non-nil error (returned here unchanged), or the control stream fails
// with something other than a timeout (also returned here, wrapped).
//
// Mirrors ServeOneCall's own frame loop, not RecvEvent: a shared control
// stream can carry other frame types between one EVENT and the next
// (nothing here assumes EVENT is the only thing this session will ever
// receive), so a wrong-frame-type parse failure is skipped and polling
// continues, exactly like ServeOneCall skips a non-"call" frame — it is
// NOT treated as a fatal error the way RecvEvent's own contract treats
// any parse failure. Confirmed live: without this, a single non-EVENT
// frame arriving on the control stream aborted the whole subscriber loop.
func (s *Session) RunSubscriber(ctx context.Context, spec frame.SubscribeSpec, id identity.KeyPair, handler EventHandler) error {
	if err := s.Subscribe(spec, id); err != nil {
		return fmt.Errorf("connection: subscribe: %w", err)
	}
	defer func() {
		_ = s.Unsubscribe(frame.NewUnsubscribeSpec(spec.Topic, spec.Realm, spec.Subscriber), id)
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		value, err := s.control.RecvFrame(time.Now().Add(subscriberPollInterval))
		if err != nil {
			if isRecvTimeout(err) {
				continue
			}
			return fmt.Errorf("connection: recv event: %w", err)
		}
		ft, ok := value.Get("frame_type")
		if !ok {
			continue
		}
		if t, _ := ft.AsText(); t != "event" {
			continue // not ours -- see this method's doc on the limitation
		}
		evt, err := frame.ParseEvent(value)
		if err != nil {
			continue // a malformed "event"-typed frame -- ignore and keep listening
		}
		if err := handler(evt); err != nil {
			return err
		}
	}
}

// isTimeout reports whether err is a read-deadline timeout from
// FrameStream.RecvFrame (a normal "nothing arrived yet" outcome for a
// polling loop), as opposed to a real connection failure.
func isRecvTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
