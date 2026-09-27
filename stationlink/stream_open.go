package stationlink

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/seal"
)

// ErrStreamOpenTooLarge is a STREAM_OPEN over the 1 MiB a peer reads of one.
var ErrStreamOpenTooLarge = errors.New("stationlink: the STREAM_OPEN is over 1 MiB")

// StreamCall is a streaming session to open: the realm and procedure, the
// provider it targets, the mode, the open's payload, how far ahead its deadline
// lies (DefaultStreamDeadline when zero), and a UCAN and its proofs for a gated
// procedure.
type StreamCall struct {
	Realm     [32]byte
	Procedure string
	Target    [32]byte
	Mode      frame.StreamMode
	Payload   cbor.Value
	Deadline  time.Duration
	Token     []byte
	Proofs    [][]byte
	// SealTo is the provider's KEM key as carried, from its verified
	// advertisement: the open's payload is sealed to it, and every later
	// frame under the stream's keys.
	SealTo []byte
	// Clear opens the stream in the clear, the application's own decision.
	// An open states SealTo or Clear, never both; one that states neither is
	// refused no_signed_state.
	Clear bool
	// Reseal, when set, lets a sealed stream refused sealed_refused before
	// it has sent anything seal once more: it is given the key id the
	// provider named (nil for none) and returns the key to seal to, and the
	// stream reopens under a new request, keeping its session. Its error, or
	// no key (no_kem_key), ends the stream: a refused sealed open is never
	// sent again in the clear. Without it, the refusal ends the stream.
	Reseal func(named *[seal.KeyIDSize]byte) ([]byte, error)
}

// OpenStream opens a streaming session: a QUIC stream of its own, on which it
// writes the signed STREAM_OPEN. A stream it opens but cannot write the open
// on is released before the error returns.
func (l *Link) OpenStream(ctx context.Context, c StreamCall) (*Stream, error) {
	if err := l.stated(c.Target, c.SealTo, c.Clear); err != nil {
		return nil, err
	}
	deadline := c.Deadline
	if deadline <= 0 {
		deadline = DefaultStreamDeadline
	}
	opened, err := l.openOn(ctx, c, c.SealTo, uint64(time.Now().Add(deadline).UnixMilli()))
	if err != nil {
		return nil, err
	}
	s := newStream(l, opened.qs, opened.open, true)
	s.sealing = opened.sealing
	if c.SealTo != nil && c.Reseal != nil {
		s.reopen = &c
	}
	if !l.holdStream(s) {
		abandon(opened.qs)
		return nil, ErrClosed
	}
	go s.read(opened.state)
	return s, nil
}

// openedStream is a STREAM_OPEN written on a QUIC stream of its own.
type openedStream struct {
	qs      *quic.Stream
	open    frame.VerifiedRequest
	state   frame.StreamState
	sealing *streamSeal
}

// openOn signs c as a STREAM_OPEN under a fresh request id with deadline (Unix
// ms), sealed to sealTo when it is set, and writes it on a new QUIC stream,
// released again when the write fails.
func (l *Link) openOn(ctx context.Context, c StreamCall, sealTo []byte, deadline uint64) (openedStream, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return openedStream{}, err
	}
	mode := c.Mode
	spec := frame.RequestSpec{RequestID: id, Realm: c.Realm, Procedure: c.Procedure, Target: c.Target,
		Deadline: deadline, Payload: c.Payload, Mode: &mode, Token: c.Token, Proofs: c.Proofs}
	var sealing *streamSeal
	if sealTo != nil {
		keys, err := l.sealRequest(&spec, seal.FrameStreamOpen, sealTo)
		if err != nil {
			return openedStream{}, err
		}
		sealing = newStreamSeal(keys, true)
	}
	signed, err := frame.SignStreamOpen(spec, l.key)
	if err != nil {
		return openedStream{}, err
	}
	encoded := cbor.Encode(signed)
	if len(encoded) > streamOpenBytes {
		return openedStream{}, fmt.Errorf("%w: %d bytes", ErrStreamOpenTooLarge, len(encoded))
	}
	open, err := frame.VerifyRequest(signed, l.profile)
	if err != nil {
		return openedStream{}, err
	}
	state, err := frame.OpenStream(open)
	if err != nil {
		return openedStream{}, err
	}
	qs, err := l.conn.OpenStreamSync(ctx)
	if err != nil {
		return openedStream{}, err
	}
	if err := (&frameWriter{w: qs}).write(encoded, streamOpenBytes); err != nil {
		abandon(qs)
		return openedStream{}, err
	}
	return openedStream{qs: qs, open: open, state: state, sealing: sealing}, nil
}

// abandon releases a QUIC stream no session holds, in both directions.
func abandon(qs *quic.Stream) {
	qs.CancelWrite(0)
	qs.CancelRead(0)
}

// holdStream keeps s among the link's streams, ended with the link; false once
// the link has ended.
func (l *Link) holdStream(s *Stream) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
		return false
	default:
	}
	l.streams[s] = struct{}{}
	return true
}

func (l *Link) forgetStream(s *Stream) {
	l.mu.Lock()
	delete(l.streams, s)
	l.mu.Unlock()
}

// endStreams ends every stream the link holds with err.
func (l *Link) endStreams(err error) {
	l.mu.Lock()
	streams := make([]*Stream, 0, len(l.streams))
	for s := range l.streams {
		streams = append(streams, s)
	}
	l.mu.Unlock()
	for _, s := range streams {
		s.end(err)
	}
}
