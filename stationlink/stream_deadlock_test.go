package stationlink_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/stationlink"
)

// Both sides of a sealed bidi stream write more than any flow-control window
// before either reads. Each side's reader has to keep reading while its own
// owner is blocked in Send, or neither window ever reopens: a reader that took
// the send mutex per received frame would deadlock the stream it is reading.
func TestBothSidesWriteBeforeEitherReads(t *testing.T) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) { assertBothSidesWriteBeforeReading(t, p) })
	}
}

// streamWriteChunks and streamWriteChunk size the writes: 4 MiB each way, well
// past quic-go's default flow-control windows.
const (
	streamWriteChunks = 128
	streamWriteChunk  = 32 * 1024
)

func assertBothSidesWriteBeforeReading(t *testing.T, p profile.Profile) {
	t.Helper()
	w := newSealedWorld(t, p, "both write")
	w.serve(t, stationlink.Offer{Procedure: "mcl-vault/count",
		Stream: &stationlink.StreamOffer{Mode: frame.Bidi, Handler: countingWithoutReading}})
	stream, err := w.caller.OpenStream(t.Context(), stationlink.StreamCall{Realm: w.realm.ID,
		Procedure: "mcl-vault/count", Target: w.provider.NodeID(), Mode: frame.Bidi,
		Payload: cbor.Map(nil), SealTo: w.key()})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	body := bytes.Repeat([]byte{1}, streamWriteChunk)
	written := make(chan error, 1)
	go func() { written <- writeChunksThenEnd(stream, body) }()
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("the caller's writes: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("the caller's writes never finished, the stream's error %v", stream.Err())
	}
	assertChunksCounted(t, stream)
}

// writeChunksThenEnd writes streamWriteChunks chunks and ends the caller's side.
func writeChunksThenEnd(stream *stationlink.Stream, body []byte) error {
	for i := 0; i < streamWriteChunks; i++ {
		if err := stream.Send(body); err != nil {
			return err
		}
	}
	return stream.CloseSend()
}

// countingWithoutReading writes its own streamWriteChunks first, then counts
// what the caller sent: the shape that only completes if each side's reader
// drains while its owner is still writing.
func countingWithoutReading(ctx context.Context, s *stationlink.Stream) error {
	body := bytes.Repeat([]byte{2}, streamWriteChunk)
	for i := 0; i < streamWriteChunks; i++ {
		if err := s.Send(body); err != nil {
			return err
		}
	}
	count := 0
	for {
		event, err := s.Recv(ctx)
		if err != nil {
			return err
		}
		if event.Kind == stationlink.StreamEnd {
			return s.Reply(cbor.Uint64(uint64(count)))
		}
		count++
	}
}

// assertChunksCounted reads the provider's chunks and checks its reply counted
// exactly the caller's.
func assertChunksCounted(t *testing.T, stream *stationlink.Stream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()
	read := 0
	for {
		event, err := stream.Recv(ctx)
		if err != nil {
			t.Fatalf("Recv after %d chunks: %v", read, err)
		}
		if event.Kind != stationlink.StreamReply {
			read++
			continue
		}
		if n, _ := event.Payload.AsInt64(); n != streamWriteChunks {
			t.Errorf("the provider counted %d chunks, want %d", n, streamWriteChunks)
		}
		return
	}
}
