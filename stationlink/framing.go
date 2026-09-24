package stationlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

// The frame size caps of a control stream, as macula 12 holds them: a
// handshake frame (OPENER, CHALLENGE, CONNECT, HELLO) is at most 64 KiB, and
// every frame after HELLO at most 16 MiB. A length header over the cap is
// refused as soon as it arrives, before its body is read.
const (
	HandshakeFrameBytes = 64 * 1024
	MaxFrameBytes       = 16 * 1024 * 1024
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

// frameWriter writes <<Len:32/big, CBOR>> frames to a stream, one at a time.
type frameWriter struct {
	mu sync.Mutex
	w  io.Writer
}

// write sends payload as one frame, refusing one over max.
func (f *frameWriter) write(payload []byte, max int) error {
	if len(payload) > max {
		return fmt.Errorf("%w: %d bytes, over %d", ErrFrameTooLarge, len(payload), max)
	}
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed, uint32(len(payload)))
	copy(framed[4:], payload)
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.w.Write(framed)
	return err
}
