package connection

import (
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/macula-io/macula-go/bolt4"
	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/ucan"
)

// overTheBudget is a payload of cbor.MaxElements items, which takes any frame
// that carries it past the decoding rule's element budget.
func overTheBudget() cbor.Value {
	items := make([]cbor.Value, cbor.MaxElements-1)
	for i := range items {
		items[i] = cbor.Uint64(0)
	}
	return cbor.List(items)
}

// overTheCap is a payload whose encoding alone is longer than the frame cap.
func overTheCap() cbor.Value {
	return cbor.Bytes(make([]byte, frame.MaxFrameBytes))
}

// servedReply has s serve one CALL, from a new caller, whose handler returns
// reply. It returns the CALL and what ServeOneCallGated returned.
func servedReply(t *testing.T, s *Session, fc *fakeControl, id identity.KeyPair, reply cbor.Value) (cbor.Value, error) {
	t.Helper()
	lookup := func([]byte, string) (CallHandler, bool) {
		return func(cbor.Value) (cbor.Value, error) { return reply, nil }, true
	}
	served := make(chan error, 1)
	go func() {
		served <- s.ServeOneCallGated(lookup, func([]byte, string) ucan.Policy { return ucan.Open }, id, 2*time.Second)
	}()
	call := signedCall(t, registryIdentity(t), "reply.probe", time.Now().Add(2*time.Second))
	fc.send(t, call)
	return call, awaitErr(t, served)
}

// A handler's reply that breaks the decoding rule, or the frame cap, is never
// written. The caller gets an ERROR in its place, with the code
// macula_station_link answers an unsendable result with, the provider logs
// the refusal, and the session stays up.
func TestAHandlerReplyRefusedBeforeItIsWrittenIsAnsweredWithAnError(t *testing.T) {
	cases := []struct {
		name  string
		reply cbor.Value
		code  bolt4.Code
	}{
		{"a reply over the element budget", overTheBudget(), bolt4.UnknownError},
		{"a reply over the frame cap", overTheCap(), bolt4.PayloadTooLarge},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, fc, id := readingSession(t)
			logged := &lockedBuffer{}
			s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
			call, err := servedReply(t, s, fc, id, c.reply)
			if err != nil {
				t.Fatalf("ServeOneCallGated = %v, want the call answered", err)
			}
			if results := fc.sentOfType(t, "result"); len(results) != 0 {
				t.Fatalf("the session wrote %d RESULT frames, want none", len(results))
			}
			resp := fc.awaitReplyTo(t, call)
			if !resp.IsError || resp.Code != uint8(c.code) {
				t.Errorf("the reply is (error %t, code %#x), want an ERROR with code %#x", resp.IsError, resp.Code, uint8(c.code))
			}
			if !strings.Contains(logged.String(), "refused before it was written") {
				t.Errorf("the provider logged %q, want the refused reply logged", logged.String())
			}
			if err := s.Err(); err != nil {
				t.Errorf("Session.Err() = %v, want the session up", err)
			}
		})
	}
}

// A frame refused before it is written on the control stream returns the named
// error, writes nothing, and leaves the session up and sending.
func TestAPublishRefusedBeforeItIsWrittenWritesNothing(t *testing.T) {
	s, fc, id := readingSession(t)
	refusals := []struct {
		payload cbor.Value
		want    error
	}{
		{overTheBudget(), frame.ErrFrameBreaksDecodingRule},
		{overTheCap(), frame.ErrFrameTooLarge},
	}
	for _, r := range refusals {
		spec := frame.NewPublishSpec("a.topic", testRealm(), id.NodeID(), 1, r.payload, time.Now().UnixMilli())
		if err := s.Publish(spec, id); !errors.Is(err, r.want) {
			t.Errorf("Publish = %v, want %v", err, r.want)
		}
	}
	if sent := fc.sent(t); len(sent) != 0 {
		t.Fatalf("the session wrote %d frames, want none", len(sent))
	}
	if err := s.Err(); err != nil {
		t.Fatalf("Session.Err() = %v, want the session up", err)
	}
	spec := frame.NewPublishSpec("a.topic", testRealm(), id.NodeID(), 2, cbor.Null(), time.Now().UnixMilli())
	if err := s.Publish(spec, id); err != nil {
		t.Fatalf("a publish after the refusals: %v", err)
	}
	fc.awaitSentOfType(t, "publish", 1)
}

// A frame refused before it is written on a dedicated stream returns the named
// error and writes nothing.
func TestAStreamFrameRefusedBeforeItIsWrittenWritesNothing(t *testing.T) {
	stream := &fakeQUICStream{}
	fs := &FrameStream{stream: stream}
	id := registryIdentity(t)
	streamID := make([]byte, 16)

	data := frame.NewStreamDataSpec(streamID, 0, frame.Msgpack, overTheBudget(), id.NodeID())
	if err := fs.SendFrame(frame.Sign(frame.StreamData(data), id)); !errors.Is(err, frame.ErrFrameBreaksDecodingRule) {
		t.Errorf("SendFrame(STREAM_DATA) = %v, want ErrFrameBreaksDecodingRule", err)
	}
	reply := frame.NewStreamReplySpec(streamID, overTheCap(), id.NodeID())
	if err := fs.SendFrame(frame.Sign(frame.StreamReply(reply), id)); !errors.Is(err, frame.ErrFrameTooLarge) {
		t.Errorf("SendFrame(STREAM_REPLY) = %v, want ErrFrameTooLarge", err)
	}
	if stream.written != 0 {
		t.Errorf("the stream was written %d bytes, want none", stream.written)
	}
}
