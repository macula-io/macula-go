package frame

import (
	"encoding/binary"
	"errors"
	"testing"
)

// A claimed frame length past the cap is refused whatever the size of an int,
// including a length with its top bit set, which a 32-bit int reads as
// negative. The refusal is ErrFrameTooLarge, the error the wire 1.0 envelope
// vectors name this case by (frame_too_large), so a reader can tell a peer's
// oversized header from a malformed one.
func TestAFrameLengthPastTheCapIsRefusedWhateverTheIntSize(t *testing.T) {
	for _, claimed := range []uint32{MaxFrameBytes + 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFC, 0xFFFF_FFFF} {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint32(buf, claimed)
		decoded, err := Decode(buf)
		if !errors.Is(err, ErrFrameTooLarge) {
			t.Errorf("claimed length %#x: Decode = %+v, %v, want ErrFrameTooLarge", claimed, decoded, err)
		}
	}
}
