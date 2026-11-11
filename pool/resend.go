package pool

import (
	"time"

	"github.com/macula-io/macula-go/stationlink"
)

// How many publications may wait for a link to be up again, and how many bytes:
// macula-rust's MAX_WAITING (src/pool/resend.rs:24) for the count, and the
// per-link bound for the bytes, since a publication waiting is one a link
// would otherwise have held. Over either, a publication is counted unsent — a
// declaration without the byte cap would bound the entries only, and one
// publication may be frame.MaxFrameBytes, 16 MiB, so 4096 of them would be
// 64 GiB.
//
// What a pool can hold in all is (MaxSeeds + MaxDirectLinks) ×
// stationlink.MaxUnconfirmedBytes, plus this queue once: the default link
// ceiling is 16 + 8, and checkLinkLimits lets each go to maxLinkLimit 64, so
// that is 768 MiB + 32 MiB at the defaults and 4 GiB + 32 MiB at the cap.
const (
	maxWaiting      = 4096
	maxWaitingBytes = stationlink.MaxUnconfirmedBytes
	// doneRemembered is how many dealt-with publications a pool remembers, the
	// same bound as the queue: a copy handed over long after its publication
	// went out or was counted is out of reach of any held set by then.
	doneRemembered = maxWaiting
)

// UnsentPublications is how many publications this pool accepted and could not
// carry: sent on a link that ended before the station was known to have read
// them and then not sent again before subscribers would refuse them, no room to
// wait, or the pool closed with them waiting. A graceful close counts the last
// 30 seconds of publications here, though the station most likely read them, so
// the count overstates once at the end.
func (p *Pool) UnsentPublications() uint64 { return p.unsent.Load() }

// resend sends again, oldest first, what a link ended holding: each on the
// first link of the active tier that takes it, and what none takes waits for
// the next one.
func (p *Pool) resend(held []stationlink.SignedPublication) {
	for _, publication := range held {
		p.carry(publication)
	}
}

// carry sends publication on a link up now, or keeps it for the next one, or
// counts it unsent when it can go nowhere. It answers whether a link took it.
//
// Every link the publication was published to held a copy of the same signed
// bytes, and each hands its copy over when it ends, so a publication the pool
// has already dealt with — one a link took, one waiting, one counted — is
// dropped here and says nothing: without that, two links ending would queue and
// count one publication twice, and halve what the queue's bounds can carry.
func (p *Pool) carry(publication stationlink.SignedPublication) bool {
	if p.dealtWith(publication.Identity()) {
		return true
	}
	if p.isClosed() {
		p.countUnsent(publication)
		return false
	}
	if p.tooLate(publication) {
		p.countUnsent(publication)
		return false
	}
	if p.send(publication) {
		p.dealt(publication.Identity())
		return true
	}
	p.keep(publication)
	return false
}

// dealtWith reports whether this publication waits, went out, or was counted.
func (p *Pool) dealtWith(id [48]byte) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.dealtWithLocked(id)
}

// dealtWithLocked is dealtWith under p.mu.
func (p *Pool) dealtWithLocked(id [48]byte) bool {
	if _, waiting := p.waitingSeen[id]; waiting {
		return true
	}
	_, done := p.done[id]
	return done
}

// dealt records a publication the pool has finished with, keeping the newest
// doneRemembered of them.
func (p *Pool) dealt(id [48]byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.dealtLocked(id)
}

// dealtLocked is dealt under p.mu.
func (p *Pool) dealtLocked(id [48]byte) {
	if _, seen := p.done[id]; seen {
		return
	}
	p.done[id] = struct{}{}
	p.doneOrder = append(p.doneOrder, id)
	for len(p.doneOrder) > doneRemembered {
		delete(p.done, p.doneOrder[0])
		p.doneOrder = p.doneOrder[1:]
	}
}

// countUnsent counts publication unsent, once however many links held a copy of
// it, and never for one a link has already taken.
func (p *Pool) countUnsent(publication stationlink.SignedPublication) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.countLocked(publication.Identity())
}

// countLocked is countUnsent under p.mu.
func (p *Pool) countLocked(id [48]byte) {
	if p.dealtWithLocked(id) {
		return
	}
	p.unsent.Add(1)
	p.dealtLocked(id)
}

// tooLate reports whether a subscriber would refuse publication now: a re-send
// is never sent so near the end of its acceptance window that a slower clock at
// the far end would drop it.
func (p *Pool) tooLate(publication stationlink.SignedPublication) bool {
	return uint64(time.Now().UnixMilli()) > publication.ResendUntil()
}

// send writes publication on the links of the active tier, in their order,
// until one takes it: the tier rule of macula-go#79 holds by construction,
// because it is the selection Publish itself uses.
func (p *Pool) send(publication stationlink.SignedPublication) bool {
	for _, link := range p.targets() {
		if err := link.PublishSigned(publication); err == nil {
			return true
		}
	}
	return false
}

// keep holds publication until a link is up, or counts it unsent when the queue
// is full by entries or bytes, or the pool has closed. A copy of a publication
// that already waits is not kept again.
func (p *Pool) keep(publication stationlink.SignedPublication) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.dealtWithLocked(publication.Identity()) {
		return
	}
	if p.closed || len(p.waiting) >= maxWaiting || p.waitingBytes+publication.Size() > maxWaitingBytes {
		p.countLocked(publication.Identity())
		return
	}
	p.waiting = append(p.waiting, publication)
	p.waitingBytes += publication.Size()
	p.waitingSeen[publication.Identity()] = struct{}{}
}

// drainWaiting sends what waits, oldest first, on the links up now: once a new
// link has its subscriptions, and before a new publication is signed. It stops
// at the first publication no link takes, leaving the queue in its order.
// Nothing here holds the pool's own mutex across a write.
func (p *Pool) drainWaiting() {
	for {
		publication, ok := p.takeWaiting()
		if !ok {
			return
		}
		if p.tooLate(publication) {
			p.mu.Lock()
			delete(p.waitingSeen, publication.Identity())
			p.countLocked(publication.Identity())
			p.mu.Unlock()
			continue
		}
		if p.send(publication) {
			p.dealt(publication.Identity())
			p.mu.Lock()
			delete(p.waitingSeen, publication.Identity())
			p.mu.Unlock()
			continue
		}
		p.restoreWaiting(publication)
		return
	}
}

// takeWaiting removes the oldest waiting publication from the queue. It stays
// in waitingSeen until it is sent or counted, so a copy handed over meanwhile is
// still recognised as one that waits.
func (p *Pool) takeWaiting() (stationlink.SignedPublication, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || len(p.waiting) == 0 {
		return stationlink.SignedPublication{}, false
	}
	publication := p.waiting[0]
	p.waitingBytes -= publication.Size()
	p.waiting = p.waiting[1:]
	return publication, true
}

// restoreWaiting puts back a publication no link took, where it was: at the
// front, keeping the queue's order, or counted unsent once the pool has closed
// and nothing will take it.
func (p *Pool) restoreWaiting(publication stationlink.SignedPublication) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		delete(p.waitingSeen, publication.Identity())
		p.countLocked(publication.Identity())
		return
	}
	p.waiting = append([]stationlink.SignedPublication{publication}, p.waiting...)
	p.waitingBytes += publication.Size()
}

// countWaiting is what a closing pool counts unsent: every member has stopped,
// so what its link held has been handed over and counted, and what is still
// waiting here can never go out.
func (p *Pool) countWaiting() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, publication := range p.waiting {
		id := publication.Identity()
		delete(p.waitingSeen, id)
		p.unsent.Add(1)
		p.dealtLocked(id)
	}
	p.waiting, p.waitingBytes = nil, 0
}
