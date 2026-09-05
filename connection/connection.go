// Package connection implements the CONNECT/HELLO handshake, the
// Session it produces, and the control-stream application primitives
// built on top of it (CALL, PUBLISH/SUBSCRIBE/EVENT, ADVERTISE) — see
// plans/PLAN_WIRE_PROTOCOL.md §3, §6. FrameStream (frame_stream.go) is
// the reusable "send/receive signed application frames on one QUIC
// stream" primitive — Session wraps one for the control stream, and
// Session.OpenDedicatedStream/AcceptDedicatedStream hand out fresh ones
// for content transfer (§12) and streaming RPC (§13), which both run on
// dedicated streams rather than the control stream.
package connection

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// HandshakeTimeout matches HANDSHAKE_TIMEOUT_MS — its most common
// real-world trigger, per the reference implementation's own comment,
// is a protocol version mismatch (bytes accumulate but never form a
// valid frame): a client that gets this wrong just silently times out,
// not an explicit error frame.
const HandshakeTimeout = 30 * time.Second

// Session is a handshaked connection to a macula-station: the open
// control stream (CONNECT/HELLO already exchanged) and the station's
// identity as verified by the HELLO frame's own signature.
type Session struct {
	conn    *quic.Conn
	control *FrameStream
	Station frame.HelloInfo
}

// Seed is one candidate station to dial — a host/port pair, the same
// shape the Erlang reference SDK's own seed() type reduces to once a
// URL form is parsed (macula_client.erl). ConnectSeeds tries a list of
// these in order; ordering is the caller's fallback priority, not
// load-balanced or shuffled.
type Seed struct {
	Host string
	Port uint16
}

// Connect dials host:port and completes the full CONNECT/HELLO
// handshake — a convenience wrapper over ConnectSeeds for the common
// single-station case; identical behavior to calling ConnectSeeds with
// a one-element list.
//
// identity MUST be puzzle-hardened (identity.Generate or
// identity.GenerateWithPuzzle) — see that package's doc: an unhardened
// identity fails this handshake silently in the worst case (QUIC/TLS
// looks healthy right up until the HELLO never accepts).
func Connect(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (*Session, error) {
	return ConnectSeeds(ctx, []Seed{{Host: host, Port: port}}, trust, id)
}

// ConnectSeeds dials each seed in order, returning the first successful
// session. A seed that refuses or times out is not fatal on its own —
// every remaining seed is still tried — matching the reference SDK's
// own "first healthy" pool-selection behavior (macula_client.erl's
// pick_connected_link/call_first_success) at connect time. If every
// seed fails, the returned error names each one and its failure so a
// dead seed is never silent (the exact failure mode
// feedback_three_seed_stations_minimum warns about: a misconfigured
// seed logging nothing and the caller just seeing "it works" from
// whichever seeds did answer).
//
// ConnectSeeds does not itself detect or recover from a connection
// dying AFTER a successful handshake — see Session.Done for that
// signal; reconnecting and replaying subscriptions/advertisements onto
// a fresh session is the caller's responsibility (deliberately: that
// policy differs by caller — a one-shot CLI command wants none of it,
// a long-lived daemon wants exactly the reference SDK's respawn+replay
// behavior).
func ConnectSeeds(ctx context.Context, seeds []Seed, trust transport.Trust, id identity.KeyPair) (*Session, error) {
	if len(seeds) == 0 {
		return nil, fmt.Errorf("connection: no seeds given")
	}
	var errs []error
	for _, seed := range seeds {
		session, err := connectOne(ctx, seed.Host, seed.Port, trust, id)
		if err == nil {
			return session, nil
		}
		errs = append(errs, fmt.Errorf("%s:%d: %w", seed.Host, seed.Port, err))
	}
	return nil, fmt.Errorf("connection: all %d seed(s) failed: %w", len(seeds), errors.Join(errs...))
}

// connectOne is Connect's actual handshake logic, factored out so
// ConnectSeeds can run it per candidate without duplicating it.
func connectOne(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	conn, err := transport.Dial(ctx, host, port, trust)
	if err != nil {
		return nil, err
	}
	// Closes conn on every failure path below unless the handshake
	// actually completes (ok = true right before the successful return).
	// Every one of these paths used to return bare, leaking the live
	// QUIC connection -- confirmed live: a station that refuses every
	// dial (e.g. puzzle rejection) combined with a caller that retries
	// on a short fixed backoff leaks one connection per attempt, each
	// one then kept minimally alive by the transport's own keepalive.
	ok := false
	defer func() {
		if !ok {
			conn.CloseWithError(0, "handshake failed")
		}
	}()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("connection: open control stream: %w", err)
	}
	control := newFrameStream(stream)

	session := &Session{conn: conn, control: control}

	puzzleEvidence := id.PuzzleEvidence()
	spec := frame.NewConnectSpec(id.NodeID(), puzzleEvidence[:])
	connectFrame := frame.Sign(frame.Connect(spec), id)
	if err := control.SendFrame(connectFrame); err != nil {
		return nil, fmt.Errorf("connection: send CONNECT: %w", err)
	}

	deadline, _ := ctx.Deadline()
	helloValue, err := control.RecvFrame(deadline)
	if err != nil {
		return nil, err
	}

	station, err := frame.ParseHello(helloValue)
	if err != nil {
		return nil, fmt.Errorf("connection: expected a HELLO frame: %w", err)
	}
	if err := frame.Verify(helloValue, station.NodeID); err != nil {
		return nil, fmt.Errorf("connection: HELLO signature check failed: %w", err)
	}
	if !station.Accepted {
		return nil, fmt.Errorf("connection: station refused the connection (refusal_code=%v)", station.RefusalCode)
	}

	session.Station = station
	ok = true
	return session, nil
}

// Done returns a channel that closes when this session's underlying
// connection is gone — cleanly closed or dropped out from under it —
// so a caller that wants to react to a dead link (redial, alert, stop)
// doesn't have to wait for its next Call/Subscribe/etc to fail first.
// Backed by quic-go's own Conn.Context(), whose Done() channel closes
// exactly on connection loss; this was previously never called
// anywhere in this SDK. Follows the same ctx-cancellation idiom already
// used by RunSubscriber, ServeForever and KeepAdvertised rather than
// introducing a new signal shape.
func (s *Session) Done() <-chan struct{} {
	return s.conn.Context().Done()
}

// OpenDedicatedStream opens a new dedicated QUIC stream on this same
// connection, separate from the control stream — the mechanism content
// transfer (§12) and streaming RPC (§13) both use instead of the
// control stream.
func (s *Session) OpenDedicatedStream(ctx context.Context) (*FrameStream, error) {
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("connection: open dedicated stream: %w", err)
	}
	return newFrameStream(stream), nil
}

// AcceptDedicatedStream accepts the next dedicated stream the *peer*
// opens toward us — e.g. the station routing an inbound STREAM_OPEN for
// a procedure this session has Advertised (§13.2). Blocks until one
// arrives or ctx is done.
//
// The receiving side has no advance notice of why a new stream arrived;
// §7 of plans/PLAN_WIRE_PROTOCOL.md says to read the stream's own first
// frame to learn its purpose, which is exactly what a caller of this
// method does next via the returned FrameStream's own RecvFrame.
func (s *Session) AcceptDedicatedStream(ctx context.Context) (*FrameStream, error) {
	stream, err := s.conn.AcceptStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("connection: accept dedicated stream: %w", err)
	}
	return newFrameStream(stream), nil
}

// Call sends a signed CALL on the control stream and waits for the
// matching RESULT or ERROR — see FrameStream.Call.
func (s *Session) Call(procedure string, realm []byte, payload cbor.Value, deadlineMs int64, id identity.KeyPair, timeout time.Duration) (frame.CallResponse, error) {
	requestID := randomID()
	announceRPCSent(s, realm, id, requestID)
	resp, err := s.control.Call(procedure, realm, payload, deadlineMs, id, timeout)
	announceRPCCompleted(s, realm, id, requestID, resp, err)
	return resp, err
}

// CallWithUCAN is Call, attaching ucanToken (e.g. from ucan.Create) to
// the outgoing CALL — for invoking a procedure gated by a
// ucan.Policy.Required policy on the provider side.
func (s *Session) CallWithUCAN(procedure string, realm []byte, payload cbor.Value, deadlineMs int64, id identity.KeyPair, timeout time.Duration, ucanToken []byte) (frame.CallResponse, error) {
	requestID := randomID()
	announceRPCSent(s, realm, id, requestID)
	resp, err := s.control.CallWithUCAN(procedure, realm, payload, deadlineMs, id, timeout, ucanToken)
	announceRPCCompleted(s, realm, id, requestID, resp, err)
	return resp, err
}

// Publish sends a signed PUBLISH, carrying the end-to-end
// `publisher_sig` (over topic/realm/publisher/seq/payload, independent
// of frame type) so the resulting EVENT survives being relayed beyond
// one hop -- a station verifies an EVENT's per-hop `signature` against
// whichever station forwarded it, which only matches on hop 1; every
// hop after that needs publisher_sig instead. Matches the Erlang
// reference SDK's own default (pubsub_emit_publisher_sig, true since
// macula 4.6.0). Fire-and-forget — no reply is expected on the wire; a
// subscriber (this session included, if subscribed to the same
// topic/realm) receives an EVENT asynchronously, read via RecvEvent.
func (s *Session) Publish(spec frame.PublishSpec, id identity.KeyPair) error {
	unsigned := frame.Publish(spec)
	withPublisherSig := frame.SignPublisher(unsigned, id)
	return s.control.SendFrame(frame.Sign(withPublisherSig, id))
}

// Subscribe sends a signed SUBSCRIBE. Fire-and-forget.
func (s *Session) Subscribe(spec frame.SubscribeSpec, id identity.KeyPair) error {
	return s.control.SendFrame(frame.Sign(frame.Subscribe(spec), id))
}

// Unsubscribe sends a signed UNSUBSCRIBE. Fire-and-forget.
func (s *Session) Unsubscribe(spec frame.UnsubscribeSpec, id identity.KeyPair) error {
	return s.control.SendFrame(frame.Sign(frame.Unsubscribe(spec), id))
}

// Advertise sends a signed ADVERTISE (§6.9) — registers this connection
// as the handler for spec's (realm, procedure). Fire-and-forget on the
// wire; the station then routes inbound CALLs (control stream) and
// STREAM_OPENs (a fresh dedicated stream — see AcceptDedicatedStream)
// for that procedure back to this connection.
func (s *Session) Advertise(spec frame.AdvertiseSpec, id identity.KeyPair) error {
	return s.control.SendFrame(frame.Sign(frame.Advertise(spec), id))
}

// Unadvertise sends a signed UNADVERTISE. Fire-and-forget.
func (s *Session) Unadvertise(spec frame.UnadvertiseSpec, id identity.KeyPair) error {
	return s.control.SendFrame(frame.Sign(frame.Unadvertise(spec), id))
}

// RecvEvent reads the next frame and parses it as an EVENT, bounded by
// timeout. Any non-EVENT frame received first is an error, not
// silently skipped — unlike Call's response wait, a caller waiting
// specifically for a pubsub delivery has no reason to expect anything
// else to legitimately arrive first.
func (s *Session) RecvEvent(timeout time.Duration) (frame.EventInfo, error) {
	value, err := s.control.RecvFrame(time.Now().Add(timeout))
	if err != nil {
		return frame.EventInfo{}, err
	}
	return frame.ParseEvent(value)
}

// RemoteAddr is the address this session's connection is with.
func (s *Session) RemoteAddr() string {
	return s.conn.RemoteAddr().String()
}

// closeDrainMs bounds how long Close waits after its last write before
// hard-closing the connection -- see Close's own doc for why this
// exists at all. Short relative to the Erlang reference's own 5s
// draining-state upper bound (macula_peering.erl, ?DRAIN_TIMEOUT_MS):
// this side only needs to cover quic-go's own internal send-scheduling
// latency, not a full round trip's worth of protocol drain.
const closeDrainMs = 250 * time.Millisecond

// closeSendTimeout bounds the best-effort GOODBYE write itself. Found
// live 2026-09-05, via adversarial review of macula-go/pool: quic-go's
// Stream.Write can block indefinitely on flow-control credit (nothing
// in this package ever called SetWriteDeadline before), and Close is
// called from exactly the cleanup paths where a peer might be in that
// state — a pool actor's shutdown, triggered because its own outbound
// queue backed up past bound, i.e. because the peer stopped draining.
// Without this, that Close call never returns, so the goroutine
// running it never does either — for the pool, that's the actor's
// whole run() loop, which means the link never respawns and the
// pool's own Close() (which waits for it) never returns either.
const closeSendTimeout = 1 * time.Second

// Close sends a signed GOODBYE and closes the underlying QUIC
// connection, matching macula_peering_conn.erl's connected -> draining
// transition (minus the full drain-timeout bookkeeping, since this
// module isn't holding a supervisor to clean up).
//
// quic-go's Stream.Write and Stream.Close both queue data for a
// background sender goroutine and return before it's actually on the
// wire -- there is no synchronous "flush" or "wait until acked"
// primitive at this level. CloseWithError on the whole connection is
// abrupt: it does not wait for outstanding stream data to be
// delivered, so anything queued but not yet sent when it runs can be
// silently lost. Found live 2026-08-29: a PUBLISH sent immediately
// before Close (the exact shape every one-shot CLI command uses)
// intermittently never reached the peer -- confirmed by a station-side
// trace showing zero activity despite a client-side success, root-
// caused to this race by observing that a manually inserted delay
// before Close fixed it every time. Closing the stream gracefully
// first, then giving the background sender a bounded window to
// actually transmit, mirrors the Erlang reference's own bounded-drain
// approach rather than requiring a true synchronous ack (which the
// wire protocol doesn't provide for fire-and-forget frames like
// PUBLISH in the first place).
func (s *Session) Close(reason string, detail *string, id identity.KeyPair) error {
	goodbye := frame.Sign(frame.Goodbye(reason, detail), id)
	_ = s.control.stream.SetWriteDeadline(time.Now().Add(closeSendTimeout)) // bounds the write below -- see closeSendTimeout's own doc
	_ = s.control.SendFrame(goodbye)                                        // best-effort -- the connection is closing regardless
	_ = s.control.stream.Close()                                            // signal no more writes; still async, see doc above
	time.Sleep(closeDrainMs)
	return s.conn.CloseWithError(0, reason)
}
