package connection

import (
	"time"

	"github.com/macula-io/macula-go/cbor"
)

// RecvAny reads the next raw application frame off the control stream,
// without filtering by frame_type — unlike Call, RunSubscriber and
// ServeOneCall, which each wait for exactly one frame_type and discard
// (RunSubscriber, ServeOneCall) or ignore (Call) anything else. This is
// the primitive a caller that wants to demux more than one concern on a
// single session — e.g. pool's per-link actor, routing "event" frames to
// pubsub fanout and "result"/"error" frames to whichever outstanding
// Call is waiting on that call_id — needs instead of picking one of
// those single-purpose methods.
//
// Same single-reader constraint as Call/RunSubscriber/ServeOneCall: this
// must be the session's only reader while in use. A caller multiplexing
// several concerns via RecvAny is expected to do so from exactly one
// goroutine per session, the same way each of those methods already
// requires.
func (s *Session) RecvAny(deadline time.Time) (cbor.Value, error) {
	return s.control.RecvFrame(deadline)
}

// SendAny writes an already-built frame value (e.g. frame.Sign(frame.Call(spec), id))
// to the control stream, without any accompanying wait — the write-side
// counterpart to RecvAny, and what a caller building its own request/
// response correlation (instead of Call's built-in send-then-block-for-
// the-matching-reply) needs to issue the request half on its own.
//
// Same "one writer must own each send" expectation as the rest of this
// package: FrameStream.SendFrame has no internal lock, so two goroutines
// calling SendAny concurrently on one session could interleave bytes
// mid-frame on the wire.
func (s *Session) SendAny(v cbor.Value) error {
	return s.control.SendFrame(v)
}
