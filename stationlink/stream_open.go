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
}

// OpenStream opens a streaming session: a QUIC stream of its own, on which it
// writes the signed STREAM_OPEN. A stream it opens but cannot write the open
// on is released before the error returns.
func (l *Link) OpenStream(ctx context.Context, c StreamCall) (*Stream, error) {
	deadline := c.Deadline
	if deadline <= 0 {
		deadline = DefaultStreamDeadline
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, err
	}
	mode := c.Mode
	signed, err := frame.SignStreamOpen(frame.RequestSpec{RequestID: id, Realm: c.Realm, Procedure: c.Procedure,
		Target: c.Target, Deadline: uint64(time.Now().Add(deadline).UnixMilli()), Payload: c.Payload, Mode: &mode,
		Token: c.Token, Proofs: c.Proofs}, l.key)
	if err != nil {
		return nil, err
	}
	encoded := cbor.Encode(signed)
	if len(encoded) > streamOpenBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrStreamOpenTooLarge, len(encoded))
	}
	open, err := frame.VerifyRequest(signed, l.profile)
	if err != nil {
		return nil, err
	}
	state, err := frame.OpenStream(open)
	if err != nil {
		return nil, err
	}
	qs, err := l.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	s := newStream(l, qs, open, true)
	if err := s.writer.write(encoded, streamOpenBytes); err != nil {
		abandon(qs)
		return nil, err
	}
	if !l.holdStream(s) {
		abandon(qs)
		return nil, ErrClosed
	}
	go s.read(state)
	return s, nil
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
