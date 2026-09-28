package stationlink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/seal"
	"github.com/macula-io/macula-go/stationlink"
)

// A stream's seal report (macula DESIGN_E2E_SEAL_REPORT §3, §5): it settles on
// the provider's first data or reply opened under the stream's key, names that
// key, and is ErrNotSettled before; an error or a stream end settles nothing
// on a sealed stream; a served stream has none.

// held serves mcl-vault/count as a server stream that waits for release, then
// sends one chunk and replies.
func held(t *testing.T, w sealedWorld, release <-chan struct{}) {
	t.Helper()
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(ctx context.Context, s *stationlink.Stream) error {
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			if err := s.Send([]byte("one")); err != nil {
				return err
			}
			return s.Reply(cbor.Text("counted"))
		}}})
}

func TestASealedStreamsReportSettlesOnItsFirstOpenedFrame(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report sealed")
	release := make(chan struct{})
	held(t, w, release)
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: w.key()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Report(); !errors.Is(err, stationlink.ErrNotSettled) {
		t.Errorf("before any frame: %v, want ErrNotSettled", err)
	}
	close(release)
	if event, err := recv(t, stream); err != nil || event.Kind != stationlink.StreamData {
		t.Fatalf("the first frame: %+v, %v", event, err)
	}
	got, err := stream.Report()
	want := stationlink.Report{Sealed: 1, Provider: w.provider.NodeID(), SealKeyID: w.ring.CurrentID()}
	if err != nil || got != want {
		t.Errorf("after an opened chunk: %+v, %v, want %+v", got, err, want)
	}
}

func TestAClearStreamsReportIsSealed0(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report clear")
	release := make(chan struct{})
	close(release)
	held(t, w, release)
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), Clear: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv(t, stream); err != nil {
		t.Fatal(err)
	}
	got, err := stream.Report()
	if want := (stationlink.Report{Sealed: 0, Provider: w.provider.NodeID()}); err != nil || got != want {
		t.Errorf("a clear stream: %+v, %v, want %+v", got, err, want)
	}
}

// A STREAM_END travels clear on a sealed stream, so nothing about it opens:
// a sealed stream the provider ends before any data has no report.
func TestASealedStreamEndedBeforeDataHasNoReport(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report ended")
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/none", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(context.Context, *stationlink.Stream) error { return nil }}})
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/none",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: w.key()})
	if err != nil {
		t.Fatal(err)
	}
	for {
		event, err := recv(t, stream)
		if err != nil || event.Kind == stationlink.StreamEnd {
			break
		}
		if event.Kind == stationlink.StreamData || event.Kind == stationlink.StreamReply {
			t.Fatalf("the provider sent %+v", event)
		}
	}
	if _, err := stream.Report(); !errors.Is(err, stationlink.ErrNotSettled) {
		t.Errorf("a sealed stream ended before data: %v, want ErrNotSettled", err)
	}
}

// A stream whose reseal finds no key ends refused: it never reports the key it
// was first sealed to.
func TestAStreamWhoseResealFailsHasNoReport(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report reseal fails")
	release := make(chan struct{})
	close(release)
	held(t, w, release)
	stale := must[*seal.PrivateKey](t)(seal.GenerateKey(profile.PQPure)).PublicKey().Carried()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: stale,
		Reseal: func(*[seal.KeyIDSize]byte) ([]byte, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv(t, stream); err == nil {
		t.Fatal("the stream was not refused")
	}
	if _, err := stream.Report(); !errors.Is(err, stationlink.ErrNotSettled) {
		t.Errorf("a stream whose reseal failed: %v, want ErrNotSettled", err)
	}
}

// After a reseal the report names the reseal's key, never the first.
func TestAResealedStreamReportsTheResealsKey(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report resealed")
	release := make(chan struct{})
	close(release)
	held(t, w, release)
	stale := must[*seal.PrivateKey](t)(seal.GenerateKey(profile.PQPure)).PublicKey().Carried()
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/count",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: stale,
		Reseal: func(*[seal.KeyIDSize]byte) ([]byte, error) { return w.key(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv(t, stream); err != nil {
		t.Fatal(err)
	}
	got, err := stream.Report()
	want := stationlink.Report{Sealed: 1, Provider: w.provider.NodeID(), SealKeyID: w.ring.CurrentID()}
	if err != nil || got != want {
		t.Errorf("a resealed stream: %+v, %v, want %+v (never the stale %x)", got, err, want, seal.KeyID(stale))
	}
}

func TestAServedStreamHasNoReport(t *testing.T) {
	w := newSealedWorld(t, profile.PQPure, "report served")
	got := make(chan error, 1)
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/served", Stream: &stationlink.StreamOffer{Mode: frame.ServerStream,
		Handler: func(_ context.Context, s *stationlink.Stream) error {
			_, err := s.Report()
			got <- err
			return s.Reply(cbor.Text("done"))
		}}})
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID, Procedure: "mcl-vault/served",
		Target: w.provider.NodeID(), Mode: frame.ServerStream, Payload: cbor.Map(nil), SealTo: w.key()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recv(t, stream); err != nil {
		t.Fatal(err)
	}
	if err := <-got; !errors.Is(err, stationlink.ErrNotACaller) {
		t.Errorf("a served stream: %v, want ErrNotACaller", err)
	}
}
