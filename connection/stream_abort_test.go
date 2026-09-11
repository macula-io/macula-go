package connection

import (
	"errors"
	"log/slog"
	"testing"
	"time"
)

// A frame that doesn't decode on an established dedicated stream ends the
// stream: it is reset and stopped with the protocol error code, its buffer
// is released, and one drop warning says it was aborted as malformed.
func TestAnEstablishedStreamWithAFrameThatDoesNotDecodeIsAborted(t *testing.T) {
	s, _, _ := readingSession(t)
	logged := &lockedBuffer{}
	s.SetLogger(slog.New(slog.NewTextHandler(logged, nil)))
	fake := &fakeQUICStream{reads: [][]byte{{0, 0, 0, 3, 0xff, 0xff, 0xff}}, errs: []error{nil}}
	fs := &FrameStream{stream: fake, session: s}

	if _, err := fs.RecvFrame(time.Time{}); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("RecvFrame = %v, want ErrMalformedFrame", err)
	}
	if w, r := fake.cancelledWrite, fake.cancelledRead; w == nil || *w != StreamProtocolErrorCode || r == nil || *r != StreamProtocolErrorCode {
		t.Fatalf("the stream was reset with %v and stopped with %v, want both with code %d", w, r, StreamProtocolErrorCode)
	}
	if len(fs.buf) != 0 {
		t.Fatalf("the aborted stream still holds %d buffered bytes", len(fs.buf))
	}
	_, _ = fs.RecvFrame(time.Time{})
	if lines := dropWarnings(logged); len(lines) != 1 || !hasFields(lines[0], "kind=aborted_stream", "count=1", "reason=malformed") {
		t.Fatalf("drop warnings = %q, want one aborted_stream line", lines)
	}
}
