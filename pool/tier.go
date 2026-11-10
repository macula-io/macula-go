package pool

import (
	"cmp"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/macula-io/macula-go/stationlink"
)

// Tier is which list a station was named in: the seeds a pool is given are its
// public tier, the stations in Opts.FallbackSeeds its fallback tier. A pool
// with no fallback list has one tier and behaves as it did before there were
// tiers at all.
//
// Originating traffic — a publication, a station procedure, a content
// announcement — goes to the pool's active tier only. Standing registrations
// (a subscription, a served procedure, an advertisement) fan out to every link
// of both tiers, and it is that which lets two nodes on different tiers still
// reach each other.
type Tier int

const (
	// TierPublic is the tier of the pool's seeds, and of every station dialled
	// directly for a call: a station the node was handed a route to is not a
	// fallback.
	TierPublic Tier = iota
	// TierFallback is the tier of Opts.FallbackSeeds, which a pool keeps for
	// when no public station is up.
	TierFallback
)

// String names the tier as status reports it.
func (t Tier) String() string {
	switch t {
	case TierPublic:
		return "public"
	case TierFallback:
		return "fallback"
	}
	return fmt.Sprintf("tier(%d)", int(t))
}

// ActiveTier is the tier the pool's originating traffic belongs to: the public
// tier the moment any public link is up, and the fallback tier only when none
// is and a fallback list was configured. A pool with no fallback list is
// public even with every link down, so "no link up" fails exactly as it did
// before there were tiers.
func (p *Pool) ActiveTier() Tier {
	p.mu.Lock()
	members := append([]*member(nil), p.members...)
	fallbackConfigured := len(p.opts.FallbackSeeds) > 0
	p.mu.Unlock()
	for _, m := range members {
		if m.tier == TierPublic && m.current() != nil {
			return TierPublic
		}
	}
	if fallbackConfigured {
		return TierFallback
	}
	return TierPublic
}

// rttOf is the round trip a link has measured, and whether it has one. It is a
// variable only so that a test can order links whose handshakes it cannot make
// slow; targets is its only reader.
var rttOf = func(l *stationlink.Link) (time.Duration, bool) { return l.RTT() }

// targets is the links up now on the pool's active tier, fastest first: the
// lowest measured round trip goes first, a link with no measurement after
// every measured one, and two unmeasured links in the pool's own order. It is
// what an originating operation selects from; a standing registration takes
// every link of both tiers and never this.
//
// The round-trip order replaces seed order as the input, which is the whole
// mechanism (macula#201 section 4): FirstSuccess means "the order the links
// already came in", so a measured order makes the lowest round trip go first,
// and the first-N slice a publish takes keeps its meaning over the same list.
// Random is the one request the order is left out of.
func (p *Pool) targets() []*stationlink.Link {
	active := p.ActiveTier()
	return p.ordered(p.selection(&active))
}

// anyTier is every link up, in the order targets gives, whichever tier it is
// on. It is what a station procedure walks onto when the active tier has no
// link up at all: the fallback is the active tier from the moment the last
// public link ends, and an operation whose own link just ended can see that
// ending a moment before the pool's own tier reading does (macula-go#74).
func (p *Pool) anyTier() []*stationlink.Link {
	return p.ordered(p.selection(nil))
}

// ordered is links in the pool's selection order: fastest measured round trip
// first, and the pool's own order for Random.
func (p *Pool) ordered(links []*stationlink.Link) []*stationlink.Link {
	if p.opts.LinkSelection == Random {
		return links
	}
	slices.SortStableFunc(links, rttOrder)
	return links
}

// rttOrder sorts two links by the round trip each has measured: the lower
// first, a link with no measurement after every measured one, and two links the
// same or unmeasured in the order they came.
func rttOrder(a, b *stationlink.Link) int {
	aRTT, aMeasured := rttOf(a)
	bRTT, bMeasured := rttOf(b)
	switch {
	case aMeasured && !bMeasured:
		return -1
	case !aMeasured && bMeasured:
		return 1
	case !aMeasured:
		return 0
	}
	return cmp.Compare(aRTT, bRTT)
}

// stationInBothTiers is the first fallback seed the pool also has as a public
// one, as the caller wrote it. Two seeds are one station when they pin the
// same node_id, or when they name the same address: either way one station
// would carry two roles, and guessing which the caller meant would be a silent
// choice about where their traffic goes.
func stationInBothTiers(public, fallback []Seed) (Seed, bool) {
	for _, f := range fallback {
		for _, p := range public {
			if sameStation(f, p) {
				return f, true
			}
		}
	}
	return Seed{}, false
}

func sameStation(a, b Seed) bool {
	if a.NodeID != ([32]byte{}) && a.NodeID == b.NodeID {
		return true
	}
	return a.Port == b.Port && strings.EqualFold(a.Host, b.Host)
}

// address is a seed's station as an operator writes it, for errors.
func (s Seed) address() string {
	return net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port)))
}
