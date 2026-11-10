package pool

import (
	"testing"

	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/teststation"
)

// A member offers its link only while it is up: a link that has ended is not
// up, even in the instant before the member records the ending, and every
// operation that reads the pool's links in that instant must not be given it
// (macula-go#74).
func TestAMemberDoesNotOfferALinkThatHasEnded(t *testing.T) {
	s := teststation.Start(t, profile.PQPure, "member live")
	realm := teststation.NewRealm(t, profile.PQPure, "member live", org)
	p := connectWith(t, "member live caller", realm, func(*Opts) {}, s)
	eventually(t, "the link up", func() bool { return upCount(p) == 1 })
	link := p.links()[0]
	s.Drop(p.NodeID())
	eventually(t, "the link ended", func() bool { return link.Err() != nil })
	held := &member{link: link}
	if held.current() != link {
		t.Fatal("the member no longer holds the link the test ended, so there is no window to test")
	}
	if got := held.live(); got != nil {
		t.Errorf("the member offered a link that has ended (%v), want none", got.Err())
	}
	// The pool reads members through live() (pool.go, selection): a pool holding
	// only this member must offer no link at all, which fails if the call site
	// reads current() instead even when live() itself is right.
	one := &Pool{members: []*member{held}}
	if got := one.links(); len(got) != 0 {
		t.Errorf("the pool offered %d link(s), want none: the first has ended (%v)", len(got), got[0].Err())
	}
}
