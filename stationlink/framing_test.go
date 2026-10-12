package stationlink

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

// A frame after HELLO is at most 16,777,215 bytes (macula docs/design/WIRE_1_0.md
// section 3.1, ?MAX_FRAME_BYTES 16#FFFFFF), judged from the length header alone:
// 16,777,216 is one byte over, and is refused before any body arrives.
func TestALengthHeaderOneByteOverTheFrameCapIsRefused(t *testing.T) {
	if MaxFrameBytes != 16_777_215 {
		t.Errorf("MaxFrameBytes = %d, want 16,777,215", MaxFrameBytes)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], 16_777_216)
	if _, err := (frameReader{r: bytes.NewReader(header[:])}).read(MaxFrameBytes); !errors.Is(err, ErrFrameTooLarge) {
		t.Errorf("a 16,777,216-byte length header: %v, want ErrFrameTooLarge", err)
	}
}
