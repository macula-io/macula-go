package stationlink

import (
	"sync"
	"time"
)

// Which handshake version a link dials each station with, and the handshake counters, for this process (macula
// plans/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md sections 3, 4 and 6), as macula's macula_peer_versions keeps them.
//
// A station never seen is dialled with version 5. One that refused a v5 CONNECT with unsupported_version is dialled
// with version 4 for the next 10 minutes, then with 5 again. One that completed a v5 handshake in this process is
// never dialled with version 4 again: a later unsupported_version from it is refused as a downgrade
// (ErrV5DowngradeRefused), which also refuses a station rolled back below v5, until ForgetV5Peer or a restart. There
// is no timer on that memory, because a timer is also an attacker's wait.

const v4Cache = 10 * time.Minute

var versions = &peerVersions{
	seenV5: map[[32]byte]bool{}, v4Until: map[[32]byte]time.Time{}, fallbacks: map[[32]byte]uint64{},
	counters: map[string]uint64{},
}

type peerVersions struct {
	mu        sync.Mutex
	seenV5    map[[32]byte]bool
	v4Until   map[[32]byte]time.Time
	fallbacks map[[32]byte]uint64
	counters  map[string]uint64
}

// counterNames are the handshake counters HandshakeCounters reports, zero included.
var counterNames = []string{"v4_connections", "v5_connections", "v4_fallbacks", "v5_downgrade_refused",
	"v4_hello_to_v5_connect", "session_proof_invalid", "session_proof_missing", "exporter_unavailable"}

func (v *peerVersions) dialVersion(nodeID [32]byte, now time.Time) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if until, cached := v.v4Until[nodeID]; cached && now.Before(until) {
		return 4
	}
	return 5
}

// unsupportedVersion records a v4 refusal of a v5 CONNECT from nodeID: false for a node seen on v5 (a refused
// downgrade), true for one that falls back to version 4 for 10 minutes.
func (v *peerVersions) unsupportedVersion(nodeID [32]byte, now time.Time) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seenV5[nodeID] {
		v.counters["v5_downgrade_refused"]++
		return false
	}
	v.v4Until[nodeID] = now.Add(v4Cache)
	v.fallbacks[nodeID]++
	v.counters["v4_fallbacks"]++
	return true
}

func (v *peerVersions) completed(nodeID [32]byte, version int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if version == 5 {
		v.seenV5[nodeID] = true
		delete(v.v4Until, nodeID)
		v.counters["v5_connections"]++
		return
	}
	v.counters["v4_connections"]++
}

func (v *peerVersions) count(name string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.counters[name]++
}

// ForgetV5Peer forgets that this process completed a handshake v5 with the station nodeID, so a station deliberately
// rolled back below v5 is dialled again, falling back to v4. An operator action for a deliberate rollback, never
// automatic.
func ForgetV5Peer(nodeID [32]byte) {
	versions.mu.Lock()
	defer versions.mu.Unlock()
	delete(versions.seenV5, nodeID)
}

// HandshakeCounters are this process's handshake counters: links by version, v4 fallbacks, refused downgrades, and
// HELLO refusals by reason. macula-go logs nothing, so these are where a repeated fallback or a refused downgrade
// shows.
func HandshakeCounters() map[string]uint64 {
	versions.mu.Lock()
	defer versions.mu.Unlock()
	out := make(map[string]uint64, len(counterNames))
	for _, name := range counterNames {
		out[name] = versions.counters[name]
	}
	return out
}
