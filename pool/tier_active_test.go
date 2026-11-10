package pool

import (
	"testing"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/teststation"
)

// nodeRecordWire is a signed node record of key's node, for the station
// procedures that carry records.
func nodeRecordWire(t *testing.T, key *identity.NodeKey, name string) []byte {
	t.Helper()
	self, err := key.NodeID()
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	unsigned, err := record.NewNodeRecord(self, nil, 0, record.NodeRecordOptions{DisplayName: name})
	if err != nil {
		t.Fatalf("node record: %v", err)
	}
	signed, err := record.Sign(unsigned, key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return wire
}

// A station procedure is originating traffic, so it goes to the active tier
// only (macula#201 §2, §9 scenario 1). While a public link is up the pool is on
// the public tier even when that link cannot answer, and the fallback station
// must not answer in its place: the fallback holds a matching record, and the
// query must fail rather than find it there.
func TestAStationQueryStaysOnTheActiveTier(t *testing.T) {
	public, fallback, realm := tiers(t)
	fallback.Put(nodeRecordWire(t, teststation.Key(t, profile.PQPure, "fallback record"), "held by the fallback"))
	p := connectTiered(t, "tier query", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	// The public station stops answering this node, so a query it cannot answer
	// has nowhere else to go: its link stays up, so the pool stays on its tier.
	public.Silence(p.NodeID(), 30*time.Second)
	if got := p.ActiveTier(); got != TierPublic {
		t.Fatalf("the active tier is %v, want TierPublic while the link is up", got)
	}
	found, _, err := p.FindRecordsByType(t.Context(), record.TypeNodeRecord)
	if err == nil {
		t.Errorf("%d records answered while the public tier could not be reached, want the public tier's failure", len(found))
	}
}

// A record put through the pool stays on the active tier for the same reason:
// the fallback station holds nothing of the node's, counted at the station.
func TestARecordStaysOnTheActiveTier(t *testing.T) {
	public, fallback, realm := tiers(t)
	p := connectTiered(t, "tier record", realm, []*teststation.Station{public}, []*teststation.Station{fallback})
	eventually(t, "both links up", func() bool { return upCount(p) == 2 })
	public.Silence(p.NodeID(), 30*time.Second)
	if got := p.ActiveTier(); got != TierPublic {
		t.Fatalf("the active tier is %v, want TierPublic while the link is up", got)
	}
	if err := p.PutRecord(t.Context(), nodeRecordWire(t, p.key, "held by the public tier")); err == nil {
		t.Error("PutRecord was answered while the public tier could not be reached, want its failure")
	}
	observer := connect(t, "fallback observer", realm, fallback)
	found, dropped, err := observer.FindRecordsByType(t.Context(), record.TypeNodeRecord)
	if err != nil {
		t.Fatalf("FindRecordsByType at the fallback station: %v", err)
	}
	if len(found) != 0 || dropped != 0 {
		t.Errorf("the fallback station holds %d records of the node (%d dropped), want 0", len(found), dropped)
	}
}
