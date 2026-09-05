package pool

import (
	"context"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/transport"
)

// -- Opts.withDefaults(): pure, no network -- the LinkSelectionAuto/
// StationDiscovery pairing logic on its own.

func TestWithDefaultsLinkSelectionAutoPairsWithStationDiscovery(t *testing.T) {
	id := testIdentity(t)

	discoveryOff := Opts{Identity: id, Trust: transport.WebPKI{}}.withDefaults()
	if discoveryOff.LinkSelection != LinkSelectionFirstSuccess {
		t.Fatalf("LinkSelectionAuto with discovery off = %v, want LinkSelectionFirstSuccess", discoveryOff.LinkSelection)
	}

	discoveryOn := Opts{Identity: id, Trust: transport.WebPKI{}, StationDiscovery: StationDiscoveryOpts{Enabled: true}}.withDefaults()
	if discoveryOn.LinkSelection != LinkSelectionRandom {
		t.Fatalf("LinkSelectionAuto with discovery on = %v, want LinkSelectionRandom", discoveryOn.LinkSelection)
	}
	if discoveryOn.StationDiscovery.RefreshInterval != DefaultStationDiscoveryRefreshInterval {
		t.Fatalf("StationDiscovery.RefreshInterval = %v, want default %v", discoveryOn.StationDiscovery.RefreshInterval, DefaultStationDiscoveryRefreshInterval)
	}
	if discoveryOn.StationDiscovery.MaxLinks != DefaultStationDiscoveryMaxLinks {
		t.Fatalf("StationDiscovery.MaxLinks = %v, want default %d", discoveryOn.StationDiscovery.MaxLinks, DefaultStationDiscoveryMaxLinks)
	}
}

func TestWithDefaultsLinkSelectionExplicitOverridesAutoPairing(t *testing.T) {
	id := testIdentity(t)

	// Explicit FirstSuccess must survive even with discovery enabled --
	// the auto-pairing is a default, not something that clobbers a
	// caller's own choice.
	o := Opts{
		Identity:         id,
		Trust:            transport.WebPKI{},
		StationDiscovery: StationDiscoveryOpts{Enabled: true},
		LinkSelection:    LinkSelectionFirstSuccess,
	}.withDefaults()
	if o.LinkSelection != LinkSelectionFirstSuccess {
		t.Fatalf("explicit LinkSelectionFirstSuccess got overridden to %v", o.LinkSelection)
	}

	// Explicit Random with discovery OFF must also survive -- the two
	// options are independent, not mutually gated.
	o2 := Opts{
		Identity:      id,
		Trust:         transport.WebPKI{},
		LinkSelection: LinkSelectionRandom,
	}.withDefaults()
	if o2.LinkSelection != LinkSelectionRandom {
		t.Fatalf("explicit LinkSelectionRandom (discovery off) got overridden to %v", o2.LinkSelection)
	}
}

// -- selectLinks(): the shared choke point Call/Publish route through.

func TestSelectLinksFirstSuccessReturnsEveryConnectedActorUnshuffled(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	s1, s2, s3 := newFakeSession(), newFakeSession(), newFakeSession()
	dialer.script("a.example", 4433, s1)
	dialer.script("b.example", 4433, s2)
	dialer.script("c.example", 4433, s3)

	opts := testOpts(id, dialer.dial)
	opts.LinkSelection = LinkSelectionFirstSuccess
	p, err := Connect(context.Background(), []Seed{
		{Host: "a.example", Port: 4433}, {Host: "b.example", Port: 4433}, {Host: "c.example", Port: 4433},
	}, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 3 })

	selected := p.selectLinks()
	if len(selected) != 3 {
		t.Fatalf("selectLinks() returned %d actors, want 3", len(selected))
	}
	seen := map[string]bool{}
	for _, a := range selected {
		seen[a.linkKey] = true
	}
	for _, key := range []string{"a.example:4433", "b.example:4433", "c.example:4433"} {
		if !seen[key] {
			t.Fatalf("selectLinks() is missing link %s -- got %v", key, seen)
		}
	}
}

// TestSelectLinksRandomProducesMultipleOrderings proves selectLinks()
// actually shuffles under LinkSelectionRandom -- not relying on
// connectedActors()'s own incidental map-iteration variation (which
// this change deliberately does NOT depend on for LinkSelectionRandom's
// guarantee, unlike the historical LinkSelectionFirstSuccess behavior).
// 5 links gives 120 possible orderings; seeing fewer than 5 distinct
// ones across 200 calls would mean the shuffle isn't actually running.
func TestSelectLinksRandomProducesMultipleOrderings(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	seeds := make([]Seed, 5)
	sessions := make([]*fakeSession, 5)
	hosts := []string{"a.example", "b.example", "c.example", "d.example", "e.example"}
	for i, h := range hosts {
		sessions[i] = newFakeSession()
		dialer.script(h, 4433, sessions[i])
		seeds[i] = Seed{Host: h, Port: 4433}
	}

	opts := testOpts(id, dialer.dial)
	opts.LinkSelection = LinkSelectionRandom
	p, err := Connect(context.Background(), seeds, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 5 })

	distinct := map[string]bool{}
	for i := 0; i < 200; i++ {
		selected := p.selectLinks()
		if len(selected) != 5 {
			t.Fatalf("selectLinks() call %d returned %d actors, want 5", i, len(selected))
		}
		var order string
		for _, a := range selected {
			order += a.linkKey + ","
		}
		distinct[order] = true
	}
	if len(distinct) < 5 {
		t.Fatalf("selectLinks() under LinkSelectionRandom produced only %d distinct orderings across 200 calls -- shuffle doesn't appear to be running", len(distinct))
	}
}

// TestCallUnderLinkSelectionRandomCanReachEveryLink is the end-to-end
// version of the shuffle test: with every link healthy but only ONE
// (chosen per-call, unpredictably) actually answering, repeated Call()s
// under LinkSelectionRandom must eventually route to every link --
// under the old, unconditional connectedActors()-order behavior this
// was only ever an accident of map iteration; this asserts it as a
// guaranteed property of LinkSelectionRandom instead.
func TestCallUnderLinkSelectionRandomCanReachEveryLink(t *testing.T) {
	id := testIdentity(t)
	dialer := newFakeDialer()
	hosts := []string{"a.example", "b.example", "c.example"}
	sessions := make(map[string]*fakeSession, 3)
	seeds := make([]Seed, 3)
	for i, h := range hosts {
		s := newFakeSession()
		sessions[h] = s
		dialer.script(h, 4433, s)
		seeds[i] = Seed{Host: h, Port: 4433}
		autoReplyWithHostname(s, h)
	}

	opts := testOpts(id, dialer.dial)
	opts.LinkSelection = LinkSelectionRandom
	p, err := Connect(context.Background(), seeds, opts)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer p.Close()
	waitFor(t, time.Second, func() bool { return p.Status().HealthyLinks == 3 })

	answeredBy := map[string]bool{}
	deadline := time.Now().Add(5 * time.Second)
	for len(answeredBy) < 3 && time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		resp, err := p.Call(ctx, fill32(0xEE), "some.procedure", cbor.Null(), time.Second)
		cancel()
		if err != nil {
			t.Fatalf("Call: %v", err)
		}
		txt, _ := resp.Payload.AsText()
		answeredBy[txt] = true
	}
	if len(answeredBy) != 3 {
		t.Fatalf("after repeated Call()s under LinkSelectionRandom, only reached %v -- want all 3 links", answeredBy)
	}
}

// autoReplyWithHostname makes s answer EVERY CALL it receives (not just
// the first -- unlike the single-Call fixture this file's sibling test
// uses, this test issues many Call()s against the same pool and any
// link picked by the shuffle needs to keep answering) with a RESULT
// carrying hostname as the payload text, so a test can tell which link
// actually served a given Call().
func autoReplyWithHostname(s *fakeSession, hostname string) {
	go func() {
		replied := 0
		for {
			select {
			case <-s.done:
				return
			default:
			}
			frames := s.Sent()
			if len(frames) <= replied {
				time.Sleep(2 * time.Millisecond)
				continue
			}
			callID, ok := frame.FrameCallID(frames[len(frames)-1])
			replied = len(frames)
			if !ok {
				continue
			}
			s.recv <- frame.Result(frame.NewResultSpec(callID, cbor.Text(hostname), fill32(0x01)))
		}
	}()
}
