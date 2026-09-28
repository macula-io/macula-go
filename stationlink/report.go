package stationlink

import (
	"errors"

	"github.com/macula-io/macula-go/seal"
)

// Report is a caller's seal report on one exchange (macula's
// DESIGN_E2E_SEAL_REPORT): Sealed is 1 when the request that produced the
// result was sealed and its answer opened under the same key, whose id is
// SealKeyID, and 0 for a clear exchange, with SealKeyID zero. Provider is the
// node the request was addressed to, its target. It states that the sealing
// mechanism ran on this exchange, nothing more. The same three fields in every
// SDK (macula's `sealed', `provider', `seal_key_id').
type Report struct {
	Sealed    int
	Provider  [32]byte
	SealKeyID [seal.KeyIDSize]byte
}

var (
	// ErrNotSettled is a stream's report asked for before it has settled: the
	// provider has sent no data or reply opened under the stream's key (on a
	// clear stream, no data, reply or end), or the stream ended first, an
	// error included.
	ErrNotSettled = errors.New("stationlink: the stream's seal report has not settled")
	// ErrNotACaller is a report asked of a served stream: the report is the
	// caller's evidence, and the provider side has none.
	ErrNotACaller = errors.New("stationlink: a served stream has no seal report")
)

// Report is this caller stream's seal report. It settles on the provider's
// first STREAM_DATA or STREAM_REPLY opened under the stream's key, after which
// no reseal can happen; on a clear stream, on its first STREAM_DATA,
// STREAM_REPLY or STREAM_END. A sealed stream's STREAM_END travels clear and
// settles nothing, and no error settles a stream. After a reseal it names the
// reseal's key. Before it settles, and on a stream that ended first, it is
// ErrNotSettled; on a served stream, ErrNotACaller.
func (s *Stream) Report() (Report, error) {
	if !s.caller {
		return Report{}, ErrNotACaller
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case !s.settled:
		return Report{}, ErrNotSettled
	case s.sealing == nil:
		return Report{Sealed: 0, Provider: s.open.Target}, nil
	}
	return Report{Sealed: 1, Provider: s.open.Target, SealKeyID: s.sealing.keyID}, nil
}

// settleOn marks the report settled when frameType is one that settles it: on
// a sealed stream a data or reply frame that opened, on a clear one a data,
// reply or end frame. It runs after the frame is taken and before it is
// delivered, so a Recv that returns it sees the report settled.
func (s *Stream) settleOn(frameType string) {
	settles := frameType == "stream_data" || frameType == "stream_reply"
	s.mu.Lock()
	if s.sealing == nil {
		settles = settles || frameType == "stream_end"
	}
	s.settled = s.settled || settles
	s.mu.Unlock()
}
