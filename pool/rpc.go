package pool

import (
	"context"
	"errors"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/transport"
)

// connectPollInterval mirrors macula_client.erl's own
// await_connected/wait_or_give_up loop exactly (timer:sleep(50)) --
// CallStation's own wait for a freshly-dialed direct-dial link.
const connectPollInterval = 50 * time.Millisecond

// Publish fans spec out to ReplicationFactor currently-connected links,
// selected per Opts.LinkSelection (selectLinks) -- LinkSelectionRandom
// changes WHICH links get picked (a shuffled subset), never how many;
// ReplicationFactor stays the sole count control, so this composes
// safely with a small ReplicationFactor (shuffling ahead of a
// single-element slice is a no-op). Partial success counts as success,
// matching macula_client.erl's own publish/5 exactly; only a
// zero-healthy-link pool is an error.
//
// The selected links publish concurrently, and Publish returns as soon as
// one of them has written the PUBLISH: a stalled link holds it up only
// when every selected link is stalled, and then no longer than the session
// send timeout, after which that session ends.
//
// payload is checked for wire admissibility HERE, in the caller's own
// goroutine, before any link is touched -- matches macula_client.erl's
// own publish/5, which does the identical check before ever calling
// into the pool, and rejects a bad payload once rather than once per
// selected link.
func (p *Pool) Publish(realm []byte, topic string, payload cbor.Value) error {
	if err := frame.CheckPayload(payload); err != nil {
		return err
	}
	sessions := p.selectLinks()
	if len(sessions) == 0 {
		return ErrNoHealthyStation
	}
	selected := sessions[:min(p.opts.ReplicationFactor, len(sessions))]

	seq := p.publishSeq.Add(1)
	spec := frame.NewPublishSpec(topic, realm, p.opts.Identity.NodeID(), seq, payload, time.Now().UnixMilli())

	results := make(chan error, len(selected))
	for _, ls := range selected {
		go func() { results <- ls.session.Publish(spec, p.opts.Identity) }()
	}
	var lastErr error
	for range selected {
		err := <-results
		if err == nil {
			return nil
		}
		lastErr = err
	}
	return lastErr
}

// Call tries currently-connected links in turn (call_first_success) and
// returns the first reply, an ERROR reply included: a provider or station
// that answered has decided. Which order it tries them in is
// Opts.LinkSelection's call (selectLinks) -- LinkSelectionFirstSuccess
// (the default absent station discovery) leaves connectedSessions()'s
// order untouched; LinkSelectionRandom shuffles it first.
//
// It moves on to the next link only when the error says the CALL was not
// sent (connection.ErrNotSent): the link's write lock stayed busy until
// the timeout, or its session had already ended. A CALL that may have
// reached its provider is never sent again, so a provider never runs one
// Call twice: a timeout after the write started is returned as it is.
func (p *Pool) Call(ctx context.Context, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	if err := frame.CheckPayload(payload); err != nil {
		return frame.CallResponse{}, err
	}
	sessions := p.selectLinks()
	if len(sessions) == 0 {
		return frame.CallResponse{}, ErrNoHealthyStation
	}
	var err error
	for _, ls := range sessions {
		var resp frame.CallResponse
		resp, err = p.callVia(ctx, ls, realm, procedure, payload, timeout)
		if !errors.Is(err, connection.ErrNotSent) {
			return resp, err
		}
	}
	return frame.CallResponse{}, err
}

// CallStation dials (or reuses) a link to host:port directly, even if it
// isn't one of the pool's configured seeds -- macula_client.erl's own
// call_station/6, the direct-dial data path. Reuse is by exact host:port
// key only.
//
// KNOWN GAP, not yet closed: if host:port names the SAME station as an
// existing seed (or another CallStation target) under a different URL
// spelling, this creates a SECOND connection to that station under the
// pool's one shared identity -- and per macula_station_listener.erl's
// per-identity peer dedupe (newer connection wins, older is kicked),
// the two links will fight forever: this dial succeeds, the station
// kicks the seed's connection, the seed link respawns and redials,
// THAT dial succeeds and gets the station to kick this one, and so on --
// a permanent ~1s flap between the two links, each replaying its
// subscriptions on every cycle, with nothing here to detect or log it.
// Closing this needs either an expected_node_id resolved up front (e.g.
// from a signed DHT record, matching call_station/8's own LinkOpts) so
// a dial can be skipped in favor of reuse BEFORE it happens, or scanning
// already-connected links' peer node-ids AFTER a dial to at least
// recognize and unwind the duplicate -- the dial itself is synchronous
// here (dialResult.nodeID, no probe round trip, unlike the Erlang
// reference's own async safe_peer_node_id), so either is cheap once
// built. Not yet wired up.
//
// Trust persists on the link for every future respawn once set -- see
// link.go's own doc on the Erlang bug (dropping a per-call trust
// override on first respawn) this avoids repeating.
func (p *Pool) CallStation(ctx context.Context, host string, port uint16, trust transport.Trust, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	if err := frame.CheckPayload(payload); err != nil {
		return frame.CallResponse{}, err
	}
	l := p.addLink(host, port, trust)

	// Captured once and reused below -- l.CurrentSession() can transition
	// to nil the instant the link dies, so calling it a second time after
	// this loop exits (instead of reusing what the loop already found)
	// would be a check-then-use race: a dead link there is a nil
	// dereference inside callVia, not just a stale read.
	var ls *linkSession
	deadline := time.Now().Add(timeout)
	for {
		if ls = l.CurrentSession(); ls != nil {
			break
		}
		if !time.Now().Before(deadline) {
			return frame.CallResponse{}, errors.New("pool: call_station: not connected")
		}
		select {
		case <-time.After(connectPollInterval):
		case <-ctx.Done():
			return frame.CallResponse{}, ctx.Err()
		}
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return frame.CallResponse{}, errors.New("pool: call_station: not connected")
	}
	return p.callVia(ctx, ls, realm, procedure, payload, remaining)
}

// callVia makes one call on ls's session, publishing no RPC facts, as
// macula_station_link:call does. It returns early when ctx ends first;
// the call itself still ends at its own timeout.
func (p *Pool) callVia(ctx context.Context, ls *linkSession, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	deadlineMs := time.Now().Add(timeout).UnixMilli()
	spec := frame.NewCallSpec(nil, procedure, realm, payload, deadlineMs, p.opts.Identity.NodeID())
	type outcome struct {
		resp frame.CallResponse
		err  error
	}
	done := make(chan outcome, 1)
	go func() {
		resp, err := ls.session.LinkCall(spec, p.opts.Identity, timeout)
		done <- outcome{resp: resp, err: err}
	}()
	select {
	case o := <-done:
		return o.resp, o.err
	case <-ctx.Done():
		return frame.CallResponse{}, ctx.Err()
	}
}
