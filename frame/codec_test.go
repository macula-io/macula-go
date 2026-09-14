package frame

import (
	"encoding/binary"
	"testing"
)

// A claimed frame length past the cap is refused whatever the size of an int,
// including a length with its top bit set, which a 32-bit int reads as
// negative.
func TestAFrameLengthPastTheCapIsRefusedWhateverTheIntSize(t *testing.T) {
	for _, claimed := range []uint32{MaxFrameBytes + 1, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFC, 0xFFFF_FFFF} {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint32(buf, claimed)
		if decoded, err := Decode(buf); err == nil {
			t.Errorf("claimed length %#x: Decode = %+v, want an error", claimed, decoded)
		}
	}
}
