package connection

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"
	"unicode/utf8"

	"github.com/macula-io/macula-go/cbor"
)

// defaultDropWarningInterval is how long a drop warning interval lasts until
// SetDropWarningInterval sets another.
const defaultDropWarningInterval = time.Minute

// maxDropProcedure is how many bytes of a procedure a drop warning carries.
const maxDropProcedure = 256

// dropKind names what a drop warning is about and dropReason why it was
// dropped, with the names every macula stack logs.
type (
	dropKind   string
	dropReason string
)

const (
	dropRefusedStreamOpen dropKind = "refused_stream_open"
	dropAbortedStream     dropKind = "aborted_stream"
	dropCall              dropKind = "dropped_call"
	dropReply             dropKind = "dropped_reply"
	dropOtherFrame        dropKind = "dropped_frame"

	// reasonUnsigned is a frame whose signature is missing or isn't 64 bytes,
	// or whose signer field is missing or isn't a 32-byte key.
	reasonUnsigned dropReason = "unsigned"
	// reasonInvalidSignature is a well-formed signature and signer that don't
	// verify.
	reasonInvalidSignature dropReason = "invalid_signature"
	// reasonMalformed is a frame missing a field it needs, or holding one of
	// the wrong type.
	reasonMalformed dropReason = "malformed"
	// reasonNotAStreamOpen is a dedicated stream whose first frame is of
	// another type.
	reasonNotAStreamOpen dropReason = "not_a_stream_open"
	// reasonUnrouted is a frame no subscription or handler matches.
	reasonUnrouted dropReason = "unrouted"
	// reasonUnexpectedType is a frame of a type not valid on the stream it
	// arrived on.
	reasonUnexpectedType dropReason = "unexpected_type"
	// reasonUnknownCallID is a RESULT or ERROR for no pending call.
	reasonUnknownCallID dropReason = "unknown_call_id"
)

// dropWindow is one kind's drop warning interval: open from the drop logged
// at once until the interval ends, counting the drops after that one along
// with the most recent one's reason and detail.
type dropWindow struct {
	open    bool
	counted uint64
	reason  dropReason
	detail  slog.Attr
}

// SetDropWarningInterval sets how long a drop warning interval lasts. The
// first inbound frame of a kind the session drops is logged at once and
// opens an interval; the drops of that kind during it are logged in one
// closing line when it ends, and there is no closing line when none came. A
// minute until set.
func (s *Session) SetDropWarningInterval(interval time.Duration) {
	s.rt.mu.Lock()
	defer s.rt.mu.Unlock()
	s.rt.dropInterval = interval
}

// warnDrop logs a drop of kind for reason, when the session has a logger: at
// once when it opens an interval, otherwise counted for the interval's
// closing line. detail is the frame's procedure or a reply's call_id prefix,
// and may be empty.
func (s *Session) warnDrop(kind dropKind, reason dropReason, detail slog.Attr) {
	s.rt.mu.Lock()
	logger := s.rt.logger
	if logger == nil {
		s.rt.mu.Unlock()
		return
	}
	if s.rt.drops == nil {
		s.rt.drops = map[dropKind]*dropWindow{}
	}
	w := s.rt.drops[kind]
	if w == nil {
		w = &dropWindow{}
		s.rt.drops[kind] = w
	}
	if w.open {
		w.counted++
		w.reason, w.detail = reason, detail
		s.rt.mu.Unlock()
		return
	}
	w.open = true
	interval, after := s.rt.dropInterval, s.rt.afterDropInterval
	s.rt.mu.Unlock()
	if interval <= 0 {
		interval = defaultDropWarningInterval
	}
	if after == nil {
		after = endDropIntervalAfter
	}
	s.logDrop(logger, kind, 1, reason, detail)
	after(interval, func() { s.endDropInterval(kind) })
}

// endDropIntervalAfter runs end once d has passed: how a drop warning interval
// ends, unless a test sets another way.
func endDropIntervalAfter(d time.Duration, end func()) {
	time.AfterFunc(d, end)
}

// endDropInterval ends kind's drop warning interval, with a closing line for
// the drops counted during it.
func (s *Session) endDropInterval(kind dropKind) {
	s.rt.mu.Lock()
	w := s.rt.drops[kind]
	if w == nil || !w.open {
		s.rt.mu.Unlock()
		return
	}
	counted, reason, detail := w.counted, w.reason, w.detail
	*w = dropWindow{}
	logger := s.rt.logger
	s.rt.mu.Unlock()
	if counted > 0 && logger != nil {
		s.logDrop(logger, kind, counted, reason, detail)
	}
}

func (s *Session) logDrop(logger *slog.Logger, kind dropKind, count uint64, reason dropReason, detail slog.Attr) {
	args := []any{"kind", string(kind), "count", count, "reason", string(reason)}
	if detail.Key != "" {
		args = append(args, detail)
	}
	args = append(args, "station", hex.EncodeToString(s.Station.NodeID))
	logger.Warn("macula: drop warning", args...)
}

// procedureDetail is a drop warning's procedure: v's procedure field cut to
// maxDropProcedure bytes without splitting a character, or nothing when v
// has none as a byte string.
func procedureDetail(v cbor.Value) slog.Attr {
	procedure := bytesField(v, "procedure")
	if procedure == nil {
		return slog.Attr{}
	}
	return slog.String("procedure", cutAtRuneStart(string(procedure), maxDropProcedure))
}

// frameTypeDetail is a dropped frame's frame_type, cut like a procedure, or
// nothing when the frame has none.
func frameTypeDetail(frameType string) slog.Attr {
	if frameType == "" {
		return slog.Attr{}
	}
	return slog.String("frame_type", cutAtRuneStart(frameType, maxDropProcedure))
}

// callIDDetail is a dropped reply's call_id: its first 4 bytes in upper-case
// hex, or nothing when the reply has no call_id.
func callIDDetail(callID []byte) slog.Attr {
	if len(callID) == 0 {
		return slog.Attr{}
	}
	return slog.String("call_id", fmt.Sprintf("%X", callID[:min(4, len(callID))]))
}

// streamIDDetail is a dropped STREAM_REPLY's stream_id: its first 4 bytes in
// upper-case hex, or nothing when the reply has none.
func streamIDDetail(streamID []byte) slog.Attr {
	if len(streamID) == 0 {
		return slog.Attr{}
	}
	return slog.String("stream_id", fmt.Sprintf("%X", streamID[:min(4, len(streamID))]))
}

// cutAtRuneStart cuts s to at most limit bytes without splitting a UTF-8
// sequence.
func cutAtRuneStart(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
