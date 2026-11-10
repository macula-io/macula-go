package pool

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/manifest"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/teststation"
)

// announcementStation is the station the announcement of mcid names, read back
// through the pool's own links.
func announcementStation(t *testing.T, p *Pool, mcid manifest.Mcid) [32]byte {
	t.Helper()
	key, err := record.ContentKey(mcid[:])
	if err != nil {
		t.Fatalf("ContentKey: %v", err)
	}
	found, _, err := p.FindRecords(t.Context(), key)
	if err != nil || len(found) != 1 {
		t.Fatalf("announcements: %d, %v", len(found), err)
	}
	a, err := record.ReadContentAnnouncement(found[0].Record())
	if err != nil {
		t.Fatalf("ReadContentAnnouncement: %v", err)
	}
	return a.ServingStation
}

// A record registered while the public tier is up names a public station: the
// announcement a sharer puts in the DHT names the station of the active tier,
// so a fallback station — a LAN address the owner keeps to itself — never goes
// into a public record. The reverse is allowed: with no public station up the
// announcement names the fallback, because that is the tier it belongs to.
func TestAPublicAnnouncementNeverNamesTheFallbackStation(t *testing.T) {
	untrusting := func(o *Opts) { o.RealmTrust = nil }
	t.Run("both tiers up", func(t *testing.T) {
		public := teststation.Start(t, profile.PQPure, "announce public")
		fallback := teststation.Start(t, profile.PQPure, "announce fallback")
		sharer := connectTieredWith(t, "announce both tiers", teststation.Realm{}, []*teststation.Station{public},
			[]*teststation.Station{fallback}, untrusting)
		eventually(t, "both links up", func() bool { return upCount(sharer) == 2 })
		mcid, err := sharer.ShareContent(t.Context(), contentRealm, pattern(10_000), "public.bin")
		if err != nil {
			t.Fatalf("ShareContent: %v", err)
		}
		if got := announcementStation(t, sharer, mcid); got != public.NodeID {
			t.Errorf("the announcement names %x, want the public station %x, never the fallback %x",
				got[:4], public.NodeID[:4], fallback.NodeID[:4])
		}
	})
	t.Run("only the fallback up", func(t *testing.T) {
		public := teststation.Start(t, profile.PQPure, "announce public away")
		fallback := teststation.Start(t, profile.PQPure, "announce fallback alone")
		public.Refuse(time.Minute)
		sharer := connectTieredWith(t, "announce fallback tier", teststation.Realm{}, []*teststation.Station{public},
			[]*teststation.Station{fallback}, untrusting)
		if got := sharer.ActiveTier(); got != TierFallback {
			t.Fatalf("the active tier is %v, want TierFallback", got)
		}
		mcid, err := sharer.ShareContent(t.Context(), contentRealm, pattern(20_000), "fallback.bin")
		if err != nil {
			t.Fatalf("ShareContent: %v", err)
		}
		if got := announcementStation(t, sharer, mcid); got != fallback.NodeID {
			t.Errorf("the announcement names %x, want the fallback station %x", got[:4], fallback.NodeID[:4])
		}
	})
}
