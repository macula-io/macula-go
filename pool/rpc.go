package pool

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/transport"
)

// publishEnqueueTimeout bounds waiting for one link's actor to accept a
// publish -- matches macula_client.erl's own default publish timeout_ms.
const publishEnqueueTimeout = 5 * time.Second

// connectPollInterval mirrors macula_client.erl's own
// await_connected/wait_or_give_up loop exactly (timer:sleep(50)) --
// CallStation's own wait for a freshly-dialed direct-dial link.
const connectPollInterval = 50 * time.Millisecond

// Publish fans spec out to ReplicationFactor currently-connected links.
// Partial success counts as success, matching macula_client.erl's own
// publish/5 exactly; only a zero-healthy-link pool is an error.
func (p *Pool) Publish(realm []byte, topic string, payload cbor.Value) error {
	actors := p.connectedActors()
	if len(actors) == 0 {
		return ErrNoHealthyStation
	}
	n := p.opts.ReplicationFactor
	if n > len(actors) {
		n = len(actors)
	}
	selected := actors[:n]

	seq := p.publishSeq.Add(1)
	spec := frame.NewPublishSpec(topic, realm, p.opts.Identity.NodeID(), seq, payload, time.Now().UnixMilli())

	var lastErr error
	anyOK := false
	for _, a := range selected {
		if err := p.publishVia(a, spec); err != nil {
			lastErr = err
			continue
		}
		anyOK = true
	}
	if anyOK {
		return nil
	}
	if lastErr == nil {
		lastErr = ErrNoHealthyStation
	}
	return lastErr
}

func (p *Pool) publishVia(a *actor, spec frame.PublishSpec) error {
	ctx, cancel := context.WithTimeout(p.ctx, publishEnqueueTimeout)
	defer cancel()
	result := make(chan error, 1)
	if err := a.send(ctx, publishCmd{spec: spec, result: result}); err != nil {
		return err
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-a.done:
		return errLinkDown
	}
}

// Call tries each currently-connected link in turn (call_first_success)
// and returns the first non-error reply.
func (p *Pool) Call(ctx context.Context, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	actors := p.connectedActors()
	if len(actors) == 0 {
		return frame.CallResponse{}, ErrNoHealthyStation
	}
	var lastErr error
	for _, a := range actors {
		resp, err := p.callVia(ctx, a, realm, procedure, payload, timeout)
		if err == nil {
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrNoHealthyStation
	}
	return frame.CallResponse{}, lastErr
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
	l := p.addLink(host, port, trust)

	// Captured once and reused below -- l.CurrentActor() can transition
	// to nil the instant the link dies, so calling it a second time after
	// this loop exits (instead of reusing what the loop already found)
	// would be a check-then-use race: a dead link there is a nil
	// dereference inside callVia, not just a stale read.
	var a *actor
	deadline := time.Now().Add(timeout)
	for {
		if a = l.CurrentActor(); a != nil {
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
	return p.callVia(ctx, a, realm, procedure, payload, remaining)
}

func (p *Pool) callVia(ctx context.Context, a *actor, realm []byte, procedure string, payload cbor.Value, timeout time.Duration) (frame.CallResponse, error) {
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		return frame.CallResponse{}, err
	}
	deadlineMs := time.Now().Add(timeout).UnixMilli()
	spec := frame.NewCallSpec(callID, procedure, realm, payload, deadlineMs, p.opts.Identity.NodeID())

	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reply := make(chan callResult, 1)
	if err := a.send(callCtx, callCmd{spec: spec, reply: reply}); err != nil {
		return frame.CallResponse{}, err
	}
	select {
	case res := <-reply:
		return res.resp, res.err
	case <-callCtx.Done():
		// Best-effort: remove the now-abandoned entry so the actor's
		// pending map doesn't leak it. Uses a fresh context -- callCtx
		// is already done, and this must not itself be skipped just
		// because the caller's own deadline passed.
		go func() { _ = a.send(context.Background(), cancelCallCmd{callID: string(callID)}) }()
		return frame.CallResponse{}, errCallTimeout
	case <-a.done:
		return frame.CallResponse{}, errLinkDown
	}
}
