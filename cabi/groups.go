package main

// #include <stdint.h>
import "C"

import (
	"context"

	"github.com/macula-io/macula-go/pool"
	"github.com/macula-io/macula-go/stationlink"
)

// Sealed groups through the ABI (macula 13.2, DESIGN_E2E_SEALED_PUBSUB.md):
// a publish sealed under a group's current epoch and a subscription that
// opens its events, each joining the group first, which pulls its epoch from
// the org's distributor over a sealed call. Unless the group's policy is
// required, the subscription also delivers clear events under the prefix,
// which any realm member can publish: a caller checks "sealed". Since
// macula-go v0.27.0-rc.3.

// groupOptionsJSON is options_json of macula_pool_publish_group and
// macula_pool_subscribe_group: the group's prefix, the org's grant (a UCAN),
// and the distributor's node id when it must be that node.
type groupOptionsJSON struct {
	Prefix      string `json:"prefix"`
	UCAN        string `json:"ucan"`
	Distributor string `json:"distributor"`
}

// groupOf reads options_json as a group.
func groupOf(text string) (pool.Group, error) {
	var o groupOptionsJSON
	if err := decodeStrict("options_json", text, &o); err != nil {
		return pool.Group{}, err
	}
	if o.Prefix == "" {
		return pool.Group{}, invalidArgument("options_json names no prefix")
	}
	g := pool.Group{Prefix: o.Prefix}
	if o.UCAN != "" {
		g.UCAN = []byte(o.UCAN)
	}
	if o.Distributor != "" {
		id, err := hexID("options_json's distributor", o.Distributor)
		if err != nil {
			return pool.Group{}, err
		}
		g.Distributor = &id
	}
	return g, nil
}

// publishGroup publishes payload on topic in realm, sealed under g.
func publishGroup(ctx context.Context, p *pool.Pool, realm [32]byte, topic, payloadJSON string, g pool.Group, ttlMs int64) error {
	if ttlMs < 0 {
		return invalidArgument("a negative ttl_ms")
	}
	payload, err := payloadFromJSON(payloadJSON)
	if err != nil {
		return err
	}
	publication := stationlink.Publication{Realm: realm, Topic: topic, Payload: payload}
	if ttlMs > 0 {
		ttl := uint64(ttlMs)
		publication.TTLMs = &ttl
	}
	return p.PublishGroup(ctx, publication, g)
}

//export macula_pool_publish_group
func macula_pool_publish_group(h C.uintptr_t, realm32 *C.uint8_t, topic, payloadJSON, optionsJSON *C.char, ttlMs,
	timeoutMs C.int64_t, token C.uintptr_t, errOut **C.char) {
	lp := poolOf(h, errOut)
	if lp == nil {
		return
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return
	}
	g, err := groupOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return
	}
	defer cancel()
	setCtxErr(ctx, errOut, publishGroup(ctx, lp.pool, realm, goString(topic), goString(payloadJSON), g, int64(ttlMs)))
}

//export macula_pool_subscribe_group
func macula_pool_subscribe_group(h C.uintptr_t, realm32 *C.uint8_t, topic, optionsJSON *C.char, timeoutMs C.int64_t,
	token C.uintptr_t, errOut **C.char) C.uintptr_t {
	lp := poolOf(h, errOut)
	if lp == nil {
		return 0
	}
	realm, err := realmOf(realm32)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	g, err := groupOf(goString(optionsJSON))
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	ctx, cancel, err := callContext(token, timeoutMs)
	if err != nil {
		setErr(errOut, err)
		return 0
	}
	defer cancel()
	sub, err := lp.pool.SubscribeGroup(ctx, realm, goString(topic), g)
	if err != nil {
		setCtxErr(ctx, errOut, err)
		return 0
	}
	return newHandle(inboxed(lp, sub))
}
