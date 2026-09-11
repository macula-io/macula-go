package connection

import (
	"sync"
	"weak"

	"github.com/macula-io/macula-go/identity"
)

// openSessions holds every handshaked session in this process by the identity
// it connected as and the station it reached. A station keeps one connection
// per identity and closes the older one when a newer handshake under the same
// identity completes, so work that would dial a station this process already
// holds a session to, under the same identity, uses that session instead (see
// SessionFor). Entries are weak: the registry never keeps a session reachable.
var openSessions = struct {
	sync.Mutex
	byKey map[sessionKey]weak.Pointer[Session]
}{byKey: map[sessionKey]weak.Pointer[Session]{}}

type sessionKey struct{ identity, station string }

func keyOf(s *Session) sessionKey {
	return sessionKey{identity: string(s.identity), station: string(s.Station.NodeID)}
}

// register makes s the session for its identity and station, replacing an
// earlier one as the station does, and forgets it once its connection ends.
func register(s *Session) {
	key, ref := keyOf(s), weak.Make(s)
	openSessions.Lock()
	openSessions.byKey[key] = ref
	openSessions.Unlock()
	go func(done <-chan struct{}) {
		<-done
		forget(key, ref)
	}(s.done)
}

// unregister forgets s, if it is still the session registered for its
// identity and station.
func unregister(s *Session) {
	forget(keyOf(s), weak.Make(s))
}

func forget(key sessionKey, ref weak.Pointer[Session]) {
	openSessions.Lock()
	defer openSessions.Unlock()
	if openSessions.byKey[key] == ref {
		delete(openSessions.byKey, key)
	}
}

// SessionFor returns the session this process holds to station under id, if
// there is one whose connection hasn't ended.
func SessionFor(id identity.KeyPair, station []byte) (*Session, bool) {
	key := sessionKey{identity: string(id.NodeID()), station: string(station)}
	openSessions.Lock()
	ref, found := openSessions.byKey[key]
	openSessions.Unlock()
	if !found {
		return nil, false
	}
	s := ref.Value()
	if s == nil || s.ended() {
		return nil, false
	}
	return s, true
}

// ended reports whether s's connection has ended.
func (s *Session) ended() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
