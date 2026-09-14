package connection

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
)

// AcceptStreamOpen accepts the next dedicated stream the station opens with a
// STREAM_OPEN whose signature verifies against the caller it names, bounded
// by ctx, reading each stream's first frame within firstFrameTimeout. A
// stream whose first frame isn't that is refused on the spot and never
// returned: it is reset and stopped with StreamRefusedCode, nothing is
// written on it, and a drop warning says why. A stream its peer ends, or
// sends nothing on, before a first frame is released the same way without a
// warning. Args that are a map carry the verified caller under "caller", as
// the 32-byte node id, replacing one the sender put there.
func (s *Session) AcceptStreamOpen(ctx context.Context, firstFrameTimeout time.Duration) (*FrameStream, frame.StreamOpenInfo, error) {
	return s.acceptStreamOpen(ctx, firstFrameTimeout, s.AcceptDedicatedStream)
}

func (s *Session) acceptStreamOpen(ctx context.Context, firstFrameTimeout time.Duration, accept func(context.Context) (*FrameStream, error)) (*FrameStream, frame.StreamOpenInfo, error) {
	var (
		fs   *FrameStream
		open frame.StreamOpenInfo
		err  error
	)
	for fs == nil && err == nil {
		fs, open, err = s.nextStreamOpen(ctx, firstFrameTimeout, accept)
	}
	return fs, open, err
}

// nextStreamOpen accepts one dedicated stream and returns it with its
// verified STREAM_OPEN, or refuses it and returns no stream and no error.
func (s *Session) nextStreamOpen(ctx context.Context, firstFrameTimeout time.Duration, accept func(context.Context) (*FrameStream, error)) (*FrameStream, frame.StreamOpenInfo, error) {
	fs, err := accept(ctx)
	if err != nil {
		return nil, frame.StreamOpenInfo{}, err
	}
	first, err := fs.recvFrame(time.Now().Add(firstFrameTimeout))
	if err != nil {
		s.releaseUnread(fs, err)
		return nil, frame.StreamOpenInfo{}, nil
	}
	open, reason := verifiedStreamOpen(first)
	if reason != "" {
		s.refuseStream(fs, reason, refusalDetail(first, reason))
		return nil, frame.StreamOpenInfo{}, nil
	}
	open.Args = withCaller(open.Args, open.Caller)
	return fs, open, nil
}

// releaseUnread refuses fs, whose first frame couldn't be read for err: with a
// drop warning when its bytes don't decode, and without one when its peer
// ended it or sent nothing in time.
func (s *Session) releaseUnread(fs *FrameStream, err error) {
	if errors.Is(err, ErrMalformedFrame) {
		s.refuseStream(fs, reasonMalformed, slog.Attr{})
		return
	}
	fs.Abort(StreamRefusedCode)
}

// verifiedStreamOpen parses first, a dedicated stream's first frame, as a
// STREAM_OPEN whose signature verifies against the caller it names, or says
// why it can't: its type first, then its signature, then its fields.
func verifiedStreamOpen(first cbor.Value) (frame.StreamOpenInfo, dropReason) {
	if frameType(first) != "stream_open" {
		return frame.StreamOpenInfo{}, reasonNotAStreamOpen
	}
	if reason := signatureReason(first, "caller"); reason != "" {
		return frame.StreamOpenInfo{}, reason
	}
	open, err := frame.ParseStreamOpen(first)
	if err != nil {
		return frame.StreamOpenInfo{}, reasonMalformed
	}
	return open, ""
}

// refuseStream resets and stops fs with StreamRefusedCode, writing nothing on
// it, and warns about it as a refused STREAM_OPEN.
func (s *Session) refuseStream(fs *FrameStream, reason dropReason, detail slog.Attr) {
	fs.Abort(StreamRefusedCode)
	s.warnDrop(dropRefusedStreamOpen, reason, detail)
}

// refusalDetail is a refused stream's drop warning detail: the procedure,
// when its first frame was a STREAM_OPEN.
func refusalDetail(first cbor.Value, reason dropReason) slog.Attr {
	if reason == reasonNotAStreamOpen {
		return slog.Attr{}
	}
	return procedureDetail(first)
}
