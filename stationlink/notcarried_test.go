package stationlink

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/frame"
)

// NotCarried is every way a link ends and a call it could not write, and
// nothing else: a station's answer, the caller's own deadline, a call over the
// frame cap and a call that timed out all leave open whether the station
// received the request, so they are not the link's failure to carry it
// (macula-go#74).
func TestNotCarriedIsEveryEndingAndNoAnswer(t *testing.T) {
	link := &Link{}
	for name, err := range map[string]error{
		"not_found":       ErrRecordNotFound,
		"refused":         &RecordRefusedError{Reason: "too_old"},
		"malformed_reply": ErrMalformedReply,
		"reply_version":   ErrReplyVersionUnsupported,
		"call_timeout":    ErrCallTimeout,
		"frame_too_large": ErrFrameTooLarge,
		"cancelled":       context.Canceled,
		"deadline":        context.DeadlineExceeded,
	} {
		if link.NotCarried(err) {
			t.Errorf("%s: the link says it did not carry a call, want a station's answer or the caller's own failure", name)
		}
	}
	for name, ending := range map[string]error{
		"liveness_lost":     ErrLivenessLost,
		"closed":            ErrClosed,
		"goodbye":           &GoodbyeError{Reason: "station_draining"},
		"status_expired":    ErrStatusExpired,
		"binding_expired":   ErrBindingExpired,
		"malformed_frame":   fmt.Errorf("%w: event", frame.ErrMalformedFrame),
		"idle_timeout":      &quic.IdleTimeoutError{},
		"closed_by_station": &quic.ApplicationError{Remote: true, ErrorMessage: "dropped"},
		"connection_lost":   errors.New("read: connection reset"),
	} {
		link.err = ending
		if !link.NotCarried(ending) {
			t.Errorf("%s: the link ended with it, want the call it was waiting for not carried", name)
		}
		if !link.NotCarried(fmt.Errorf("the call: %w", ending)) {
			t.Errorf("%s wrapped: the link ended with it, want the call not carried", name)
		}
		if link.NotCarried(ErrRecordNotFound) {
			t.Errorf("%s: a station's not_found was named as the link's ending", name)
		}
	}
	link.err = nil
	if !link.NotCarried(&callNotSent{errors.New("write: stream reset")}) {
		t.Error("a call the link could not write was carried, want it named as not carried")
	}
}
