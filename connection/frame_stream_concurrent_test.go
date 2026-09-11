package connection

import (
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// interleavingStream takes a Write's bytes one at a time and lets other
// writers in between them. quic-go serializes concurrent Writes on a
// stream, but documents concurrent Write as not permitted, so FrameStream
// can't rely on that.
type interleavingStream struct {
	fakeQUICStream
	mu      sync.Mutex
	written []byte
}

func (s *interleavingStream) Write(p []byte) (int, error) {
	for _, b := range p {
		s.mu.Lock()
		s.written = append(s.written, b)
		s.mu.Unlock()
		runtime.Gosched()
	}
	return len(p), nil
}

// Frames sent on one stream from several goroutines at once are written
// whole, whatever the stream does with concurrent writes.
func TestConcurrentSendFramesAreWrittenWhole(t *testing.T) {
	stream := &interleavingStream{}
	fs := &FrameStream{stream: stream}
	const senders, perSender = 8, 25
	start := make(chan struct{})
	var wg sync.WaitGroup
	for s := range senders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range perSender {
				text := fmt.Sprintf("sender %d frame %d %s", s, i, strings.Repeat("x", 64))
				if err := fs.SendFrame(cbor.Text(text)); err != nil {
					t.Errorf("SendFrame: %v", err)
					return
				}
			}
		}()
	}
	close(start)
	wg.Wait()

	seen := map[string]bool{}
	buf := stream.written
	for len(buf) > 0 {
		decoded, err := frame.Decode(buf)
		if err != nil || !decoded.Complete {
			t.Fatalf("after %d whole frames the remaining %d bytes don't form a frame (decode error: %v)", len(seen), len(buf), err)
		}
		text, _ := decoded.Frame.AsText()
		seen[text] = true
		buf = buf[decoded.Consumed:]
	}
	if len(seen) != senders*perSender {
		t.Fatalf("decoded %d distinct frames, want %d", len(seen), senders*perSender)
	}
}
