package stationlink

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// stalledWriter is a stream whose writes never finish until it is released,
// as a QUIC stream whose peer stopped reading.
type stalledWriter struct{ release chan struct{} }

func (w stalledWriter) Write(p []byte) (int, error) {
	<-w.release
	return len(p), nil
}

// A send stalled on the network holds no lock a receive needs: a Recv, and its
// cancellation, go on while the send waits.
func TestAStalledSendDoesNotBlockARecv(t *testing.T) {
	key, err := identity.GenerateIdentityKey(profile.PQPure, 0)
	if err != nil {
		t.Fatal(err)
	}
	stalled := stalledWriter{release: make(chan struct{})}
	defer close(stalled.release)
	// A bidi open this key made, so the key can sign the caller's frames.
	bidi := frame.Bidi
	open := frame.VerifiedRequest{FrameType: "stream_open", Caller: key.KeyID(), Mode: &bidi}
	s := &Stream{link: &Link{key: key, profile: profile.PQPure}, writer: &frameWriter{w: stalled}, open: open,
		caller: true, inboxBound: streamInbox, notify: make(chan struct{}, 1), done: make(chan struct{})}

	sending := make(chan error, 1)
	go func() { sending <- s.SendValue(cbor.Text("stuck")) }()
	time.Sleep(50 * time.Millisecond) // the send is now inside its write

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := s.Recv(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Recv while a send is stalled: %v, want its own deadline", err)
	}
	if waited := time.Since(started); waited > 2*time.Second {
		t.Fatalf("Recv waited %v behind a stalled send", waited)
	}
	s.deliver(StreamEvent{Kind: StreamData, Body: cbor.Text("still readable")}, 1)
	event, err := s.Recv(context.Background())
	if text, _ := event.Body.AsText(); err != nil || text != "still readable" {
		t.Fatalf("a frame delivered during a stalled send: %v, %v", event, err)
	}
	select {
	case err := <-sending:
		t.Fatalf("the stalled send returned early: %v", err)
	default:
	}
}
