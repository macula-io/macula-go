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
	v4Links: map[[32]byte]map[*Link]struct{}{}, counters: map[string]uint64{},
}

type peerVersions struct {
	mu        sync.Mutex
	seenV5    map[[32]byte]bool
	v4Until   map[[32]byte]time.Time
	fallbacks map[[32]byte]uint64
	v4Links   map[[32]byte]map[*Link]struct{} // this process's open v4 links, by station
	counters  map[string]uint64
}

// counterNames are the handshake counters HandshakeCounters reports, zero included.
var counterNames = []string{"v4_connections", "v5_connections", "v4_fallbacks", "v5_downgrade_refused",
	"v4_hello_to_v5_connect", "session_proof_invalid", "session_proof_missing", "exporter_unavailable"}

func (v *peerVersions) dialVersion(nodeID [32]byte, now time.Time) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seenV5[nodeID] {
		return 5
	}
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

// completed records link's handshake with its station, in the link's version,
// so that no ordering keeps a v4 link to a node this process has seen on v5
// (macula#53). A v4 link to a node seen on v5 is ErrV5DowngradeRefused; any
// other v4 link is registered, under the same lock as the check, and a later v5
// completion with that node ends every registered one as a downgrade.
func (v *peerVersions) completed(nodeID [32]byte, link *Link) error {
	superseded, err := v.recorded(nodeID, link)
	for _, old := range superseded {
		old.end(ErrV5DowngradeRefused)
	}
	return err
}

// recorded is completed under the lock: it returns the v4 links a v5
// completion supersedes, to be ended outside it.
func (v *peerVersions) recorded(nodeID [32]byte, link *Link) ([]*Link, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case link.version == 5:
		v.seenV5[nodeID] = true
		delete(v.v4Until, nodeID)
		v.counters["v5_connections"]++
		superseded := make([]*Link, 0, len(v.v4Links[nodeID]))
		for old := range v.v4Links[nodeID] {
			superseded = append(superseded, old)
			v.counters["v5_downgrade_refused"]++
		}
		delete(v.v4Links, nodeID)
		return superseded, nil
	case v.seenV5[nodeID]:
		v.counters["v5_downgrade_refused"]++
		return nil, ErrV5DowngradeRefused
	}
	if v.v4Links[nodeID] == nil {
		v.v4Links[nodeID] = map[*Link]struct{}{}
	}
	v.v4Links[nodeID][link] = struct{}{}
	v.counters["v4_connections"]++
	return nil, nil
}

// v4Ended forgets a v4 link that ended.
func (v *peerVersions) v4Ended(nodeID [32]byte, link *Link) {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.v4Links[nodeID], link)
	if len(v.v4Links[nodeID]) == 0 {
		delete(v.v4Links, nodeID)
	}
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
