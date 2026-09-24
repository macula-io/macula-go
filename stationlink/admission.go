package stationlink

import (
	"sync"

	"github.com/macula-io/macula-go/frame"
)

// Admission of the CALLs a provider receives, as macula_request_admission
// judges them: a request runs once. Its deadline must lie between the
// provider's clock minus 5 minutes and plus 10 minutes, and (caller,
// request_id) must be new; the entry is kept until the deadline plus 5
// minutes. A copy with the same request hash gets the stored reply, or
// request_copy while the first still runs; one with another hash is refused.
// The entries are bounded, and a full bound refuses rather than evicts: each
// caller holds at most admissionCallerQuota entries, the link at most
// admissionCap, and stored replies at most admissionReplyBytes per caller and
// admissionReplyBytesTotal in all. A reply past either is not kept, and a copy
// of its request is refused reply_not_kept.
const (
	deadlinePastToleranceMs = 5 * 60_000
	deadlineAheadMaxMs      = 10 * 60_000
	keptPastDeadlineMs      = 5 * 60_000
)

// The bounds, macula's defaults for one share.
var (
	admissionCallerQuota     = 256
	admissionCap             = 1024
	admissionReplyBytes      = 256 * 1024
	admissionReplyBytesTotal = 16 * 1024 * 1024
)

type admissionKey struct {
	caller    [32]byte
	requestID [16]byte
}

type admissionEntry struct {
	hash      [48]byte
	expiresAt int64
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

type admission struct {
	mu         sync.Mutex
	entries    map[admissionKey]*admissionEntry
	callers    map[[32]byte]int
	replyBytes map[[32]byte]int
	replyTotal int
}

func newAdmission() *admission {
	return &admission{entries: map[admissionKey]*admissionEntry{}, callers: map[[32]byte]int{},
		replyBytes: map[[32]byte]int{}}
}

// admit judges request at nowMs, sweeping the entries that expired first.
func (a *admission) admit(request frame.VerifiedRequest, nowMs int64) verdict {
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
	case a.callers[request.Caller] >= admissionCallerQuota:
		return verdict{refusal: "caller_quota"}
	case len(a.entries) >= admissionCap:
		return verdict{refusal: "admission_full"}
	}
	a.entries[key] = &admissionEntry{hash: request.RequestHash, expiresAt: deadline + keptPastDeadlineMs}
	a.callers[request.Caller]++
	return verdict{}
}

// store keeps the encoded reply of an admitted request for its copies, when the
// byte bounds leave room for it.
func (a *admission) store(request frame.VerifiedRequest, reply []byte) {
	a.mu.Lock()
	defer a.mu.Unlock()
	entry, held := a.entries[admissionKey{request.Caller, request.RequestID}]
	if !held || entry.answered || entry.hash != request.RequestHash {
		return
	}
	entry.answered = true
	if a.replyBytes[request.Caller]+len(reply) > admissionReplyBytes || a.replyTotal+len(reply) > admissionReplyBytesTotal {
		return
	}
	entry.reply = reply
	a.replyBytes[request.Caller] += len(reply)
	a.replyTotal += len(reply)
}

// sweep removes the entries whose deadline plus 5 minutes passed before nowMs.
func (a *admission) sweep(nowMs int64) {
	for key, entry := range a.entries {
		if entry.expiresAt >= nowMs {
			continue
		}
		delete(a.entries, key)
		a.callers[key.caller]--
		if a.callers[key.caller] == 0 {
			delete(a.callers, key.caller)
		}
		if entry.reply != nil {
			a.replyBytes[key.caller] -= len(entry.reply)
			a.replyTotal -= len(entry.reply)
			if a.replyBytes[key.caller] == 0 {
				delete(a.replyBytes, key.caller)
			}
		}
	}
}
