package stationlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/macula-io/macula-go/frame"
)

// The frame size caps of a control stream: a handshake frame (OPENER,
// CHALLENGE, CONNECT, HELLO) is at most 64 KiB, and every frame after HELLO at
// most 16,777,215 bytes, frame.MaxFrameBytes (macula's ?MAX_FRAME_BYTES,
// WIRE_1_0.md section 3.1). A length header over the cap is refused as soon as
// it arrives, before its body is read.
const (
	HandshakeFrameBytes = 64 * 1024
	MaxFrameBytes       = frame.MaxFrameBytes
)

// ErrFrameTooLarge is a frame whose length header exceeds the cap in force.
var ErrFrameTooLarge = errors.New("stationlink: frame longer than the cap in force")

// frameReader reads <<Len:32/big, CBOR>> frames from a stream.
type frameReader struct {
	r io.Reader
}

// read returns the next frame's CBOR bytes, refusing a length header over max.
func (f frameReader) read(max int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if uint64(length) > uint64(max) {
		return nil, fmt.Errorf("%w: %d bytes, over %d", ErrFrameTooLarge, length, max)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(f.r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// errFrameRefused is a frame the writer was not allowed to send: hold refused
// it, which no byte of it having gone out is the same thing as.
var errFrameRefused = errors.New("stationlink: the frame was refused before it was written")

// frameWriter writes <<Len:32/big, CBOR>> frames to a stream, one at a time.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
	// frames counts the frames written, and a frame's number is how many went
	// before it: numbered under mu, so the numbers follow the order the frames
	// go onto the stream.
	frames uint64
}

// write sends payload as one frame, refusing one over max.
func (f *frameWriter) write(payload []byte, max int) error {
	_, _, err := f.writeNumbered(payload, max, nil)
	return err
}

// writeNumbered sends payload as one frame and answers its number on the
// stream and the bytes that went out. hold, when set, runs once the number is
// taken and before the first byte is written, under the writer's mutex, and
// answers whether the frame may go out: that is what lets a publication be held
// before any of it can leave, so a link that ends in between still carries it.
// A refused frame wrote nothing and answers errFrameRefused.
func (f *frameWriter) writeNumbered(payload []byte, max int, hold func(number uint64) bool) (number uint64, n int, err error) {
	if len(payload) > max {
		return 0, 0, fmt.Errorf("%w: %d bytes, over %d", ErrFrameTooLarge, len(payload), max)
	}
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed, uint32(len(payload)))
	copy(framed[4:], payload)
	f.mu.Lock()
	defer f.mu.Unlock()
	number = f.frames
	f.frames++
	if hold != nil && !hold(number) {
		return number, 0, errFrameRefused
	}
	n, err = f.w.Write(framed)
	return number, n, err
}
