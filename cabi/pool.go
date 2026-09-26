package main

// #include <stdint.h>
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/pool"
)

// livePool is a pool with what the ABI keeps beside it: its link events'
// inbox, and the inboxes of its subscriptions and served procedures, which
// end when it closes.
type livePool struct {
	pool   *pool.Pool
	events *inbox

	mu     sync.Mutex
	closed bool
	owned  map[*inbox]struct{}
}

// own ties box to the pool: it closes when the pool does. A pool already
// closed closes it at once.
func (lp *livePool) own(box *inbox) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	if lp.closed {
		box.close()
		return
	}
	lp.owned[box] = struct{}{}
}

func (lp *livePool) disown(box *inbox) {
	lp.mu.Lock()
	defer lp.mu.Unlock()
	delete(lp.owned, box)
}

func (lp *livePool) close() {
	_ = lp.pool.Close()
	lp.mu.Lock()
	lp.closed = true
	owned := lp.owned
	lp.owned = nil
	lp.mu.Unlock()
	for box := range owned {
		box.close()
	}
	lp.events.close()
}

// connectSeed is one seed as a binding gives it.
type connectSeed struct {
	Host   string `json:"host"`
	Port   uint16 `json:"port"`
	NodeID string `json:"node_id"`
}

// connectOptions are the pool options a binding gives; realm keys are hex,
// keyed by the realm id in hex.
type connectOptions struct {
	RealmTrust        map[string]string `json:"realm_trust"`
	ReplicationFactor int               `json:"replication_factor"`
	MaxSeeds          int               `json:"max_seeds"`
	MaxDirectLinks    int               `json:"max_direct_links"`
	RespawnDelayMs    int64             `json:"respawn_delay_ms"`
	TimeoutMs         int64             `json:"timeout_ms"`
}

// decodeStrict decodes JSON text into v, refusing unknown fields, so a
// misspelt option fails instead of being ignored.
func decodeStrict(what, text string, v any) error {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return invalidArgument("%s: %v", what, err)
	}
	return nil
}

func hexID(what, text string) ([32]byte, error) {
	raw, err := hex.DecodeString(text)
	if err != nil || len(raw) != 32 {
		return [32]byte{}, invalidArgument("%s must be 64 hex characters", what)
	}
	return [32]byte(raw), nil
}

// connect connects a pool of key's node to seeds, returning once one link is
// up, within the options' timeout (30 s by default) or until base ends. Its
// error is already classified against its own deadline.
func connect(base context.Context, key *identity.NodeKey, seedsJSON, optionsJSON string) (*livePool, error) {
	var seeds []connectSeed
	if err := decodeStrict("seeds", seedsJSON, &seeds); err != nil {
		return nil, err
	}
	var opts connectOptions
	if optionsJSON != "" {
		if err := decodeStrict("options", optionsJSON, &opts); err != nil {
			return nil, err
		}
	}
	poolSeeds := make([]pool.Seed, len(seeds))
	for i, s := range seeds {
		id, err := hexID("a seed's node_id", s.NodeID)
		if err != nil {
			return nil, err
		}
		poolSeeds[i] = pool.Seed{Host: s.Host, Port: s.Port, NodeID: id}
	}
	trust := map[[32]byte][]byte{}
	for realmHex, keyHex := range opts.RealmTrust {
		realm, err := hexID("a realm id", realmHex)
		if err != nil {
			return nil, err
		}
		realmKey, err := hex.DecodeString(keyHex)
		if err != nil {
			return nil, invalidArgument("a realm key is not hex: %v", err)
		}
		trust[realm] = realmKey
	}
	timeoutMs := opts.TimeoutMs
	if timeoutMs == 0 {
		timeoutMs = 30_000
	}
	ctx, cancel, err := withTimeout(base, timeoutMs)
	if err != nil {
		return nil, err
	}
	defer cancel()
	lp := &livePool{events: newInbox(dropOldest), owned: map[*inbox]struct{}{}}
	p, err := pool.Connect(ctx, poolSeeds, pool.Opts{IdentityKey: key, RealmTrust: trust,
		ReplicationFactor: opts.ReplicationFactor, MaxSeeds: opts.MaxSeeds, MaxDirectLinks: opts.MaxDirectLinks,
		RespawnDelay:  time.Duration(opts.RespawnDelayMs) * time.Millisecond,
		OnLinkEvent:   lp.linkEvent,
		OnIssuerError: lp.issuerError})
	if err != nil {
		return nil, classify(ctx, err)
	}
	lp.pool = p
	return lp, nil
}

func (lp *livePool) linkEvent(e pool.LinkEvent) {
	var reason any
	if e.Err != nil {
		reason = e.Err.Error()
	}
	lp.pushEvent(map[string]any{"kind": "link", "station": hex.EncodeToString(e.Station[:]),
		"direct": flag(e.Direct), "up": flag(e.Up), "error": reason})
}

func (lp *livePool) issuerError(err error) {
	lp.pushEvent(map[string]any{"kind": "issuer_error", "error": err.Error()})
}

func (lp *livePool) pushEvent(event map[string]any) {
	text, _ := json.Marshal(event)
	lp.events.push(context.Background(), inboxItem{json: string(text)})
}

// flag is a boolean as the ABI's JSON carries it: 1 or 0.
func flag(b bool) int {
	if b {
		return 1
	}
	return 0
}

//export macula_pool_connect
func macula_pool_connect(keyHandle C.uintptr_t, seedsJSON, optionsJSON *C.char, token C.uintptr_t,
	errOut **C.char) C.uintptr_t {
	key := keyOf(keyHandle, errOut)
	if key == nil {
		return 0
	}
	base, cancel, err := callContext(token, 0)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	defer cancel()
	lp, err := connect(base, key, goString(seedsJSON), goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	return newHandle(lp)
}

func poolOf(h C.uintptr_t, errOut **C.char) *livePool {
	lp, ok := valueOf[*livePool](h)
	if !ok {
		setErr(errOut, errInvalidHandle)
		return nil
	}
	return lp
}

//export macula_pool_close
func macula_pool_close(h C.uintptr_t) {
	if lp, ok := valueOf[*livePool](h); ok {
		lp.close()
		release(h)
	}
}

//export macula_pool_node_id
func macula_pool_node_id(h C.uintptr_t, out *C.uint8_t, errOut **C.char) {
	if lp := poolOf(h, errOut); lp != nil {
		id := lp.pool.NodeID()
		writeFixed(out, id[:])
	}
}

// statusJSON is the pool's links.
func statusJSON(p *pool.Pool) string {
	type link struct {
		Station string `json:"station"`
		Host    string `json:"host"`
		Port    uint16 `json:"port"`
		Direct  int    `json:"direct"`
		Up      int    `json:"up"`
	}
	links := []link{}
	for _, s := range p.Status() {
		links = append(links, link{Station: hex.EncodeToString(s.Station[:]), Host: s.Host, Port: s.Port,
			Direct: flag(s.Direct), Up: flag(s.Up)})
	}
	text, _ := json.Marshal(links)
	return string(text)
}

//export macula_pool_status
func macula_pool_status(h C.uintptr_t, errOut **C.char) *C.char {
	lp := poolOf(h, errOut)
	if lp == nil {
		return nil
	}
	return cString(statusJSON(lp.pool))
}

//export macula_pool_events_next
func macula_pool_events_next(h C.uintptr_t, timeoutMs C.int64_t, token C.uintptr_t, closed *C.int32_t,
	errOut **C.char) *C.char {
	lp := poolOf(h, errOut)
	if lp == nil {
		*closed = 0
		return nil
	}
	return takeNext(lp.events, token, timeoutMs, nil, closed, errOut)
}
