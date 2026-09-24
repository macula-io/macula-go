package stationlink

import (
	"errors"
	"sync"

	"github.com/macula-io/macula-go/frame"
)

// Admission of the CALLs a provider node receives, as macula_request_admission
// judges them: a request runs once, whichever of the node's links it arrives
// on. Its deadline must lie between the provider's clock minus 5 minutes and
// plus 10 minutes, and (caller, request_id) must be new; the entry is kept
// until the deadline plus 5 minutes. A copy with the same request hash gets the
// stored reply, or request_copy while the first still runs; one with another
// hash is refused. The entries are bounded, and a full bound refuses rather
// than evicts, in this order: each caller holds at most CallerQuota entries,
// each share (one link's place: the station it dialed) at most Share, and the
// admission at most Cap; stored replies take at most ReplyBytes per caller and
// ReplyBytesTotal in all. A reply past either is not kept, and a copy of its
// request is refused reply_not_kept.
const (
	deadlinePastToleranceMs = 5 * 60_000
	deadlineAheadMaxMs      = 10 * 60_000
	keptPastDeadlineMs      = 5 * 60_000
)

// AdmissionLimits are an Admission's bounds.
type AdmissionLimits struct {
	CallerQuota     int
	Share           int
	Cap             int
	ReplyBytes      int
	ReplyBytesTotal int
}

// DefaultAdmissionLimits are macula's defaults, with Cap one share's worth:
// the bound of an admission a single link holds. A pool sets Cap to Share
// times the most links it holds.
func DefaultAdmissionLimits() AdmissionLimits {
	return AdmissionLimits{CallerQuota: 256, Share: 1024, Cap: 1024, ReplyBytes: 256 * 1024, ReplyBytesTotal: 16 * 1024 * 1024}
}

// ErrInvalidAdmissionLimits is a bound that is not positive, or a caller quota
// over the share or a caller's reply bytes over the total, as macula refuses.
var ErrInvalidAdmissionLimits = errors.New("stationlink: admission limits must be positive, with caller quota <= share and reply bytes <= total")

// Validate reports whether the limits are ones macula would start with.
func (l AdmissionLimits) Validate() error {
	if l.CallerQuota <= 0 || l.Share <= 0 || l.Cap <= 0 || l.ReplyBytes <= 0 || l.ReplyBytesTotal <= 0 ||
		l.CallerQuota > l.Share || l.ReplyBytes > l.ReplyBytesTotal {
		return ErrInvalidAdmissionLimits
	}
	return nil
}

type admissionKey struct {
	caller    [32]byte
	requestID [16]byte
}

type admissionEntry struct {
	hash      [48]byte
	expiresAt int64
	share     string
	answered  bool
	reply     []byte // nil when answered but not kept
}

// verdict is the admission's judgement of a request: a refusal code, a copy
// with its stored reply (nil while the first still runs), or new.
type verdict struct {
	refusal string
	copy    bool
	stored  []byte
}

// Admission is one provider node's request admission, shared by all its links.
type Admission struct {
	limits     AdmissionLimits
	mu         sync.Mutex
	entries    map[admissionKey]*admissionEntry
	callers    map[[32]byte]int
	shares     map[string]int
	replyBytes map[[32]byte]int
	replyTotal int
}

// NewAdmission is an empty admission with limits, which must Validate; a link
// given limits that do not is refused at Dial.
func NewAdmission(limits AdmissionLimits) *Admission {
	return &Admission{limits: limits, entries: map[admissionKey]*admissionEntry{}, callers: map[[32]byte]int{},
		shares: map[string]int{}, replyBytes: map[[32]byte]int{}}
}

// admit judges request arriving on share at nowMs, sweeping the entries that
// expired first.
func (a *Admission) admit(request frame.VerifiedRequest, share string, nowMs int64) verdict {
	deadline := int64(request.Deadline)
	switch {
	case deadline < nowMs-deadlinePastToleranceMs:
		return verdict{refusal: "expired"}
	case deadline > nowMs+deadlineAheadMaxMs:
		return verdict{refusal: "not_yet_valid"}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sweep(nowMs)
	key := admissionKey{request.Caller, request.RequestID}
	if entry, held := a.entries[key]; held {
		switch {
		case entry.hash != request.RequestHash:
			return verdict{refusal: "request_id_reused"}
		case entry.answered && entry.reply == nil:
			return verdict{refusal: "reply_not_kept"}
		}
		return verdict{copy: true, stored: entry.reply}
	}
	switch {
	case a.callers[request.Caller] >= a.limits.CallerQuota:
		return verdict{refusal: "caller_quota"}
	case a.shares[share] >= a.limits.Share:
		return verdict{refusal: "share_full"}
	case len(a.entries) >= a.limits.Cap:
		return verdict{refusal: "admission_full"}
	}
	a.entries[key] = &admissionEntry{hash: request.RequestHash, expiresAt: deadline + keptPastDeadlineMs, share: share}
	a.callers[request.Caller]++
	a.shares[share]++
	return verdict{}
}

// store keeps the encoded reply of an admitted request for its copies, when the
// byte bounds leave room for it.
func (a *Admission) store(request frame.VerifiedRequest, reply []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, held := a.entries[admissionKey{request.Caller, request.RequestID}]
	if !held || entry.answered || entry.hash != request.RequestHash {
		return
	}
	entry.answered = true
	if a.replyBytes[request.Caller]+len(reply) > a.limits.ReplyBytes || a.replyTotal+len(reply) > a.limits.ReplyBytesTotal {
		return
	}
	entry.reply = reply
	a.replyBytes[request.Caller] += len(reply)
	a.replyTotal += len(reply)
}

// sweep removes the entries whose deadline plus 5 minutes passed before nowMs.
func (a *Admission) sweep(nowMs int64) {
	for key, entry := range a.entries {
		if entry.expiresAt >= nowMs {
			continue
		}
		delete(a.entries, key)
		decrement(a.callers, key.caller, 1)
		decrement(a.shares, entry.share, 1)
		if entry.reply != nil {
			decrement(a.replyBytes, key.caller, len(entry.reply))
			a.replyTotal -= len(entry.reply)
		}
	}
}

// decrement takes n from m[k], dropping the key at zero.
func decrement[K comparable](m map[K]int, k K, n int) {
	m[k] -= n
	if m[k] <= 0 {
		delete(m, k)
	}
}
