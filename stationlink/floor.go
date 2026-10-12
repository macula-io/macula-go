package stationlink

import (
	"sync"
)

// Each station's handshake floor for this process (macula docs/design/WIRE_1_0.md
// section 4.6): the highest handshake version a link completed with it. A link
// never completes below it, so a station rolled back below the version this
// process last met it on is refused as version_below_floor rather than
// trusted. macula-go has no writable store of its own, so the floor lasts the
// run, as the design allows for an SDK host.

var floors = &handshakeFloors{floor: map[[32]byte]int64{}, counters: map[string]uint64{}}

type handshakeFloors struct {
	mu       sync.Mutex
	floor    map[[32]byte]int64
	counters map[string]uint64
}

// counterNames are the handshake counters HandshakeCounters reports, zero
// included.
var counterNames = []string{"connections", "downgrade_detected", "version_below_floor", "session_proof_invalid",
	"session_proof_missing", "exporter_unavailable"}

// of is the floor for nodeID, 0 for a station this process never completed a
// handshake with.
func (f *handshakeFloors) of(nodeID [32]byte) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.floor[nodeID]
}

// completed records a handshake completed with nodeID in version.
func (f *handshakeFloors) completed(nodeID [32]byte, version int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.floor[nodeID] = max(f.floor[nodeID], version)
	f.counters["connections"]++
}

func (f *handshakeFloors) count(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.counters[name]++
}

// HandshakeCounters are this process's handshake counters: links completed,
// and handshakes refused by reason (a detected downgrade, a version below the
// floor, a session proof that does not verify or is missing, a TLS exporter
// that gave no value). macula-go logs nothing, so these are where a refused
// downgrade shows.
func HandshakeCounters() map[string]uint64 {
	floors.mu.Lock()
	defer floors.mu.Unlock()
	out := make(map[string]uint64, len(counterNames))
	for _, name := range counterNames {
		out[name] = floors.counters[name]
	}
	return out
}
