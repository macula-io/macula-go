package frame

import (
	"encoding/binary"
	"fmt"

	"github.com/macula-io/macula-go-sdk/cbor"
)

// Encode wraps frameVal as <Length:4 bytes big-endian><Cbor>.
func Encode(frameVal cbor.Value) ([]byte, error) {
	payload := cbor.Encode(frameVal)
	if len(payload) > MaxFrameBytes {
		return nil, fmt.Errorf("frame: encode: frame is %d bytes, exceeding the %d-byte cap", len(payload), MaxFrameBytes)
	}
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(out, uint32(len(payload)))
	copy(out[4:], payload)
	return out, nil
}

// Decoded is the three-way result of attempting to decode one frame
// from the head of a buffer, mirroring the reference decoder's
// {ok,_,_} / {more,_} / {error,_} contract.
type Decoded struct {
	// Frame is the decoded value, valid only when Complete is true.
	Frame cbor.Value
	// Consumed is how many bytes Frame took from the front of buf, valid
	// only when Complete is true.
	Consumed int
	// Complete reports whether a full frame was decoded. When false,
	// NeedMore says at least how many more bytes are needed before
	// trying again.
	Complete bool
	NeedMore int
}

// Decode decodes one length-prefixed frame from the head of buf.
func Decode(buf []byte) (Decoded, error) {
	if len(buf) < 4 {
		return Decoded{NeedMore: 4 - len(buf)}, nil
	}
	length := int(binary.BigEndian.Uint32(buf[:4]))
	if length > MaxFrameBytes {
		return Decoded{}, fmt.Errorf("frame: decode: claimed frame length %d exceeds the %d-byte cap", length, MaxFrameBytes)
	}
	if len(buf) < 4+length {
		return Decoded{NeedMore: 4 + length - len(buf)}, nil
	}
	value, consumed, err := cbor.Decode(buf[4 : 4+length])
	if err != nil {
		return Decoded{}, fmt.Errorf("frame: decode: %w", err)
	}
	if consumed != length {
		return Decoded{}, fmt.Errorf("frame: decode: cbor consumed %d bytes, frame declared %d", consumed, length)
	}
	return Decoded{Frame: value, Consumed: 4 + length, Complete: true}, nil
}
