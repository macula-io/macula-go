package connection

import (
	"io"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// fakeQUICStream is a minimal quicStream for exercising RecvFrame's
// read loop without a real QUIC connection. Read results are consumed
// in order, one per call.
type fakeQUICStream struct {
	reads [][]byte
	errs  []error
	idx   int
}

func (f *fakeQUICStream) Read(p []byte) (int, error) {
	if f.idx >= len(f.reads) {
		return 0, io.EOF
	}
	data := f.reads[f.idx]
	err := f.errs[f.idx]
	f.idx++
	return copy(p, data), err
}

func (f *fakeQUICStream) Write(p []byte) (int, error)      { return len(p), nil }
func (f *fakeQUICStream) Close() error                     { return nil }
func (f *fakeQUICStream) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeQUICStream) SetWriteDeadline(time.Time) error { return nil }

// TestRecvFrame_FinalChunkWithEOF is a regression test for a real bug:
// RecvFrame's read loop discarded the bytes from a Read call that
// returned data together with io.EOF in the same call. io.Reader's own
// contract explicitly permits this ("Callers should always process the
// n > 0 bytes returned before considering the error") and quic-go does
// exactly this when a peer's final STREAM frame carries both the last
// data and the FIN bit -- confirmed live against real production
// (macula-io/macula#8) via qlog: the peer's reply arrived completely
// and cleanly, on the wire, but the caller still reported
// "read stream: EOF" because the just-appended final byte was never
// given a chance to complete the frame decode before the error won.
func TestRecvFrame_FinalChunkWithEOF(t *testing.T) {
	want := "the whole reply, delivered on time"
	encoded, err := frame.Encode(cbor.Text(want))
	if err != nil {
		t.Fatalf("frame.Encode: %v", err)
	}
	if len(encoded) < 2 {
		t.Fatalf("test setup: encoded frame too short to split, got %d bytes", len(encoded))
	}
	split := len(encoded) - 1

	fs := &FrameStream{
		stream: &fakeQUICStream{
			reads: [][]byte{encoded[:split], encoded[split:]},
			errs:  []error{nil, io.EOF},
		},
	}

	got, err := fs.RecvFrame(time.Time{})
	if err != nil {
		t.Fatalf("RecvFrame returned an error for a fully-delivered frame: %v", err)
	}
	gotText, ok := got.AsText()
	if !ok || gotText != want {
		t.Fatalf("RecvFrame = %#v, want Text(%q)", got, want)
	}
}

// TestRecvFrame_GenuineEOFBeforeCompleteFrame confirms the fix didn't
// overcorrect: a stream that ends (EOF, zero bytes) before a complete
// frame has actually arrived must still surface as an error, not hang
// or silently return a zero-value frame.
func TestRecvFrame_GenuineEOFBeforeCompleteFrame(t *testing.T) {
	fs := &FrameStream{
		stream: &fakeQUICStream{
			reads: [][]byte{{0, 0, 0}}, // 3 bytes: not even a full 4-byte length prefix
			errs:  []error{io.EOF},
		},
	}

	_, err := fs.RecvFrame(time.Time{})
	if err == nil {
		t.Fatalf("RecvFrame should error on a genuinely incomplete frame at EOF, got nil")
	}
}
