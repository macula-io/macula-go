package connection

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
)

// streamOpenFrom is an unsigned STREAM_OPEN for procedure naming caller.
func streamOpenFrom(caller identity.KeyPair, procedure string) cbor.Value {
	streamID := make([]byte, 16)
	copy(streamID, procedure)
	spec := frame.NewStreamOpenSpec(streamID, procedure, testRealm(), frame.ServerStream, cbor.Null(),
		time.Now().Add(time.Minute).UnixMilli(), caller.NodeID())
	return frame.StreamOpen(spec)
}

// arrivingStream is a dedicated stream accepted on s whose peer sent data,
// or nothing when data is nil, and then finished.
func arrivingStream(s *Session, data []byte) (*FrameStream, *fakeQUICStream) {
	fake := &fakeQUICStream{}
	if data != nil {
		fake.reads, fake.errs = [][]byte{data}, []error{nil}
	}
	return &FrameStream{stream: fake, session: s}, fake
}

func encoded(t *testing.T, v cbor.Value) []byte {
	t.Helper()
	b, err := frame.Encode(v)
	if err != nil {
		t.Fatalf("frame.Encode: %v", err)
	}
	return b
}

// A dedicated stream is refused for the first thing wrong with its first
// frame and never handed to the provider: it is reset and stopped with the
// refusal code, nothing is written on it, and a drop warning says why, with
// the procedure when the frame was a STREAM_OPEN. A stream its peer finishes
// before any frame is released the same way, without a warning. The verified
// STREAM_OPEN after each is the one accepted.
func TestAStreamOpenIsRefusedForTheFirstThingWrongWithIt(t *testing.T) {
	caller, other := registryIdentity(t), registryIdentity(t)
	cases := []struct {
		name    string
		first   []byte
		warning []string
	}{
		{"signed by another", encoded(t, frame.Sign(streamOpenFrom(caller, "forged"), other)), []string{"reason=invalid_signature", "procedure=forged"}},
		{"unsigned", encoded(t, streamOpenFrom(caller, "unsigned")), []string{"reason=unsigned", "procedure=unsigned"}},
		{"another frame type", encoded(t, frame.Sign(frame.StreamEnd(frame.NewStreamEndSpec(make([]byte, 16), frame.Send, caller.NodeID())), caller)), []string{"reason=not_a_stream_open"}},
		{"bytes that don't decode", []byte{0, 0, 0, 3, 0xff, 0xff, 0xff}, []string{"reason=malformed"}},
		{"a verified STREAM_OPEN missing its mode", encoded(t, frame.Sign(withoutField(streamOpenFrom(caller, "no.mode"), "mode"), caller)), []string{"reason=malformed", "procedure=no.mode"}},
		{"finished before any frame", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := readingSession(t)
			logged := &lockedBuffer{}
			s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
			refused, refusedFake := arrivingStream(s, tc.first)
			genuine, genuineFake := arrivingStream(s, encoded(t, frame.Sign(streamOpenFrom(caller, "genuine"), caller)))
			pending := []*FrameStream{refused, genuine}
			accept := func(context.Context) (*FrameStream, error) {
				next := pending[0]
				pending = pending[1:]
				return next, nil
			}

			fs, open, err := s.acceptStreamOpen(context.Background(), time.Second, accept)
			if err != nil || fs != genuine || open.Procedure != "genuine" {
				t.Fatalf("accepted %q (err %v), want only the verified STREAM_OPEN", open.Procedure, err)
			}
			if c := refusedFake.cancels; len(c) != 2 || c[0] != StreamRefusedCode || c[1] != StreamRefusedCode {
				t.Fatalf("the refused stream was cancelled with %v, want one reset and one stop, both with code %d", c, StreamRefusedCode)
			}
			if refusedFake.written != 0 {
				t.Fatalf("%d bytes written on the refused stream, want none", refusedFake.written)
			}
			if len(genuineFake.cancels) != 0 {
				t.Fatal("the accepted stream was cancelled")
			}
			lines := dropWarnings(logged)
			if tc.warning == nil {
				if len(lines) != 0 {
					t.Fatalf("drop warnings = %q, want none", lines)
				}
				return
			}
			if len(lines) != 1 || !hasFields(lines[0], append([]string{"kind=refused_stream_open", "count=1"}, tc.warning...)...) {
				t.Fatalf("drop warnings = %q, want one refused_stream_open line with %q", lines, tc.warning)
			}
			if !strings.Contains(strings.Join(tc.warning, " "), "procedure=") && strings.Contains(lines[0], "procedure=") {
				t.Fatalf("drop warning %q names a procedure, want none", lines[0])
			}
		})
	}
}

// openStreamWith opens a stream on conn and writes v on it as its first frame.
func openStreamWith(t *testing.T, ctx context.Context, conn *quic.Conn, v cbor.Value) *quic.Stream {
	t.Helper()
	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatalf("OpenStreamSync: %v", err)
	}
	if _, err := st.Write(encoded(t, v)); err != nil {
		t.Fatalf("writing the first frame: %v", err)
	}
	return st
}

// A STREAM_OPEN not signed by the caller it names is never handed to the
// provider, and over QUIC its opener sees the stream reset and stopped with
// the refusal code.
func TestAStreamOpenNotSignedByItsCallerIsRefused(t *testing.T) {
	s, _, _ := readingSession(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", selfSignedServerTLSConfig(t), &quic.Config{})
	if err != nil {
		t.Fatalf("quic.ListenAddr: %v", err)
	}
	defer ln.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opener, err := quic.DialAddr(ctx, ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"macula-test"}}, &quic.Config{})
	if err != nil {
		t.Fatalf("quic.DialAddr: %v", err)
	}
	defer opener.CloseWithError(0, "test done")
	provider, err := ln.Accept(ctx)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	defer provider.CloseWithError(0, "test done")

	caller, other := registryIdentity(t), registryIdentity(t)
	forged := openStreamWith(t, ctx, opener, frame.Sign(streamOpenFrom(caller, "forged"), other))
	openStreamWith(t, ctx, opener, frame.Sign(streamOpenFrom(caller, "genuine"), caller))

	_, open, err := s.acceptStreamOpen(ctx, 5*time.Second, func(ctx context.Context) (*FrameStream, error) {
		st, err := provider.AcceptStream(ctx)
		if err != nil {
			return nil, err
		}
		return newFrameStream(st), nil
	})
	if err != nil || open.Procedure != "genuine" {
		t.Fatalf("accepted %q (err %v), want only the STREAM_OPEN signed by its caller", open.Procedure, err)
	}

	var refused *quic.StreamError
	_ = forged.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := forged.Read(make([]byte, 1)); !errors.As(err, &refused) || refused.ErrorCode != StreamRefusedCode || !refused.Remote {
		t.Fatalf("reading the forged stream: %v, want it reset with code %d", err, StreamRefusedCode)
	}
	stopped := time.Now().Add(5 * time.Second)
	for {
		_, err := forged.Write([]byte{0})
		if errors.As(err, &refused) && refused.ErrorCode == StreamRefusedCode && refused.Remote {
			break
		}
		if err != nil {
			t.Fatalf("writing the forged stream: %v, want it stopped with code %d", err, StreamRefusedCode)
		}
		if time.Now().After(stopped) {
			t.Fatal("the forged stream was never stopped")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A control stream frame whose bytes don't decode ends the session, and the
// session's error says the frame was malformed.
func TestAControlFrameThatDoesNotDecodeEndsTheSessionAsMalformed(t *testing.T) {
	s, fc, _ := readingSession(t)
	fc.inbound <- []byte{0, 0, 0, 3, 0xff, 0xff, 0xff}
	select {
	case <-s.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the session didn't end")
	}
	if err := s.Err(); !errors.Is(err, ErrSessionEnded) || !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("the session ended with %v, want ErrSessionEnded wrapping ErrMalformedFrame", err)
	}
}
