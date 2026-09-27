package stationlink

import (
	"context"
	"errors"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/seal"
)

// A sealed stream (macula 13's E2E design §5.2): its STREAM_OPEN agreed two
// keys, and every later STREAM_DATA, STREAM_REPLY and STREAM_ERROR is sealed
// under the key for its direction. A caller's frames seal under k_c2p with
// their seq as the nonce; a provider's under k_p2c with a random nonce each,
// carried, since a provider restarted by a retried open numbers from 0 again.
// A STREAM_END has nothing to seal. The plaintext of a raw chunk is its bytes,
// of a structured chunk or a reply the value's CBOR, and of a STREAM_ERROR
// cbor([code, message]), as macula_stream's plain_of/1 has them.

// maxSealedProviderFrames bounds the frames a provider seals under its random
// nonces on one stream: GCM's bound, as macula's max_sealed_frames.
const maxSealedProviderFrames = 1 << 32

// ErrSealedFramesExhausted is a provider stream that has sealed
// maxSealedProviderFrames frames: another would pass GCM's nonce bound.
var ErrSealedFramesExhausted = errors.New("stationlink: this sealed stream has sealed all the frames it may")

// streamSeal is one side's keys for a sealed stream.
type streamSeal struct {
	keyID     [seal.KeyIDSize]byte
	requestID [16]byte
	caller    bool
	send      [32]byte
	recv      [32]byte
}

func newStreamSeal(s *callSeal, caller bool) *streamSeal {
	ss := &streamSeal{keyID: s.keyID, requestID: s.request.RequestID, caller: caller, send: s.kP2C, recv: s.kC2P}
	if caller {
		ss.send, ss.recv = s.kC2P, s.kP2C
	}
	return ss
}

func (ss *streamSeal) sendDirection() seal.Direction {
	if ss.caller {
		return seal.CallerToProvider
	}
	return seal.ProviderToCaller
}

func (ss *streamSeal) recvDirection() seal.Direction {
	if ss.caller {
		return seal.ProviderToCaller
	}
	return seal.CallerToProvider
}

// sealed is fields, numbered seq, with its body, payload or code and message
// sealed. A STREAM_END goes as it is.
func (ss *streamSeal) sealed(fields frame.StreamFields, seq uint64) (frame.StreamFields, error) {
	if !ss.caller && seq >= maxSealedProviderFrames {
		return nil, ErrSealedFramesExhausted
	}
	var frameType string
	var plain []byte
	switch f := fields.(type) {
	case frame.StreamDataFields:
		frameType = "stream_data"
		if f.Encoding == frame.Raw {
			b, ok := f.Body.AsBytes()
			if !ok {
				return nil, frame.ErrOutOfRange
			}
			plain = b
		} else {
			if err := frame.CheckPayload(f.Body); err != nil {
				return nil, err
			}
			plain = cbor.Encode(f.Body)
		}
	case frame.StreamReplyFields:
		frameType = "stream_reply"
		if err := frame.CheckPayload(f.Payload); err != nil {
			return nil, err
		}
		plain = cbor.Encode(f.Payload)
	case frame.StreamErrorFields:
		frameType = "stream_error"
		plain = seal.ErrorPlain(f.Code, f.Message)
	default:
		return fields, nil
	}
	var nonce [seal.NonceSize]byte
	var carried []byte
	if ss.caller {
		nonce = seal.StreamNonce(seq)
	} else {
		nonce = seal.RandomNonce()
		carried = nonce[:]
	}
	sealed := &frame.Sealed{KeyID: ss.keyID, Nonce: carried,
		Ct: seal.Seal(ss.send, nonce, seal.StreamAAD(frameType, ss.requestID, seq, ss.sendDirection()), plain)}
	switch f := fields.(type) {
	case frame.StreamDataFields:
		return frame.StreamDataFields{Seq: f.Seq, Encoding: f.Encoding, Sealed: sealed}, nil
	case frame.StreamReplyFields:
		return frame.StreamReplyFields{Seq: f.Seq, Sealed: sealed}, nil
	case frame.StreamErrorFields:
		return frame.StreamErrorFields{Seq: f.Seq, Sealed: sealed}, nil
	}
	return fields, nil
}

// opened is a verified sealed frame from the peer with its body, payload, or
// code and message opened; one that does not open, or opens to nothing its
// type holds, is an error.
func (ss *streamSeal) opened(v frame.VerifiedStreamFrame) (frame.VerifiedStreamFrame, error) {
	if v.Sealed.KeyID != ss.keyID {
		// As macula_stream's opened/5: a frame naming another key than the
		// stream's is not opened.
		return v, errNotOpened
	}
	var nonce [seal.NonceSize]byte
	if ss.caller {
		if len(v.Sealed.Nonce) != seal.NonceSize {
			return v, errNotOpened
		}
		nonce = [seal.NonceSize]byte(v.Sealed.Nonce)
	} else {
		nonce = seal.StreamNonce(v.Seq)
	}
	plain, err := seal.Open(ss.recv, nonce, seal.StreamAAD(v.FrameType, ss.requestID, v.Seq, ss.recvDirection()), v.Sealed.Ct)
	if err != nil {
		return v, errNotOpened
	}
	switch v.FrameType {
	case "stream_data":
		if v.Encoding == frame.Raw {
			v.Body = cbor.Bytes(plain)
			return v, nil
		}
		v.Body, err = cbor.Decode(plain)
	case "stream_reply":
		v.Payload, err = cbor.Decode(plain)
	case "stream_error":
		v.Code, v.Message, err = seal.OpenErrorPlain(plain)
	}
	if err != nil {
		return v, errNotOpened
	}
	return v, nil
}

var errNotOpened = errors.New("stationlink: a sealed stream frame that does not open")

// resealed reopens a sealed caller stream that the provider refused
// sealed_refused before this side sent anything: sealed once more, to the key
// StreamCall.Reseal gives for the key the refusal names, under a new request
// on a new QUIC stream, keeping this Stream and its session (macula's
// sealed_refused_arrived/2 and reopen). It reports whether it took the
// refusal: false leaves the refusal to end the stream. Sends wait while it
// reopens, and go out under the new open.
func (s *Stream) resealed(refused *StreamError) bool {
	c := s.reopen
	s.reopen = nil
	if c == nil {
		return false
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.mu.Lock()
	sent := s.sendSeq
	s.mu.Unlock()
	if sent != 0 {
		return false
	}
	key, err := c.Reseal(refusedKey(&refused.Message))
	if err == nil && key == nil {
		// A refused sealed open is never sent again in the clear.
		err = &ConfidentialityError{Reason: ReasonNoKEMKey}
	}
	if err != nil {
		s.end(err)
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	// The reopen keeps the first open's deadline, as macula's
	// reopened_client_stream/5 does: resealing does not extend the stream.
	s.mu.Lock()
	deadline := s.open.Deadline
	s.mu.Unlock()
	opened, err := s.link.openOn(ctx, *c, key, deadline)
	cancel()
	if err != nil {
		s.end(err)
		return true
	}
	s.mu.Lock()
	old := s.qs
	s.qs, s.writer, s.open, s.sealing = opened.qs, &frameWriter{w: opened.qs}, opened.open, opened.sealing
	s.mu.Unlock()
	abandon(old)
	go s.read(opened.state)
	return true
}

// errClearOnSealed is a clear frame on a sealed stream that nothing clear may
// carry: a downgrade.
var errClearOnSealed = errors.New("stationlink: a clear frame on a sealed stream")

// unsealed is a verified frame from the peer as the stream takes it, as
// macula_stream's peer_event/2 does. A clear stream takes no sealed frame:
// that ends the session as sealed_refused, this node holding no key for it. A
// sealed stream opens each sealed frame before anything of it takes effect,
// and takes nothing clear but a STREAM_END and, on a caller's side, the
// provider's refusal of the open at seq 0: sealed_refused, or one from the
// closed set; each ends the stream as its StreamError. Anything else clear is
// errClearOnSealed, and a frame that does not open errNotOpened.
func (s *Stream) unsealed(v frame.VerifiedStreamFrame) (frame.VerifiedStreamFrame, error) {
	switch {
	case s.sealing == nil && v.Sealed != nil:
		return v, &StreamError{Code: codeSealedRefused, Message: noKeyDetail}
	case s.sealing == nil:
		return v, nil
	case v.Sealed != nil:
		return s.sealing.opened(v)
	case v.FrameType == "stream_end":
		return v, nil
	case s.caller && v.FrameType == "stream_error" && v.Seq == 0 && (v.Code == codeSealedRefused || IsClearRefusal(v.Code)):
		return v, &StreamError{Code: v.Code, Message: v.Message}
	}
	return v, errClearOnSealed
}
