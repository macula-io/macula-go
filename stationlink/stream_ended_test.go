package stationlink_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/stationlink"
)

// A stream whose link the station drops carries the link's ending to whoever is
// reading it: the session did not fail on its own, the link under it did, and a
// caller can tell the two apart (macula-go#75).
func TestAStreamWhoseLinkEndsNamesTheEnding(t *testing.T) {
	w := newStreamWorld(t, "ended stream")
	handlerRunning := make(chan struct{}, 1)
	w.serve(t, frame.ServerStream, func(ctx context.Context, _ *stationlink.Stream) error {
		select {
		case handlerRunning <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	})
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	select {
	case <-handlerRunning:
	case <-time.After(10 * time.Second):
		t.Fatal("the provider never started the session")
	}
	w.station.Drop(w.caller.NodeID())

	_, err := recv(t, stream)
	if !errors.Is(err, stationlink.ErrLinkEnded) {
		t.Fatalf("the stream of an ended link: %v, want the link's ending", err)
	}
	if got := stationlink.EndReason(err); got != "closed_by_station" {
		t.Errorf("EndReason: %q, want closed_by_station", got)
	}
	if !strings.Contains(err.Error(), "(closed_by_station)") {
		t.Errorf("the message does not name the ending: %v", err)
	}
}

// A stream whose link its own owner closes is named as the link's ending too:
// end ends every stream it still holds with the ending wrapped, so a reader
// sees the link and not the bare ErrClosed the link ended with (macula-go#75).
func TestAStreamWhoseLinkItsOwnerClosesNamesTheEnding(t *testing.T) {
	w := newStreamWorld(t, "owner-closed stream")
	w.serve(t, frame.ServerStream, func(ctx context.Context, _ *stationlink.Stream) error {
		<-ctx.Done()
		return ctx.Err()
	})
	stream := w.open(t, frame.ServerStream, cbor.Map(nil))
	stationlink.EndLink(w.caller, stationlink.ErrClosed)

	_, err := recv(t, stream)
	if !errors.Is(err, stationlink.ErrLinkEnded) {
		t.Fatalf("the stream of a link its owner closed: %v, want the link's ending", err)
	}
	if got := stationlink.EndReason(err); got != "closed" {
		t.Errorf("EndReason: %q, want closed", got)
	}
	if !strings.Contains(err.Error(), "(closed)") {
		t.Errorf("the message does not name the ending: %v", err)
	}
}
