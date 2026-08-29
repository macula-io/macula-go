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
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go-sdk/cbor"
	"github.com/macula-io/macula-go-sdk/frame"
	"github.com/macula-io/macula-go-sdk/identity"
	"github.com/macula-io/macula-go-sdk/transport"
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

// Connect dials host:port and completes the full CONNECT/HELLO
// handshake: open a QUIC connection, open the control stream, send a
// signed CONNECT built from identity, and wait for a HELLO whose own
// signature verifies against the node_id it claims.
//
// identity MUST be puzzle-hardened (identity.Generate or
// identity.GenerateWithPuzzle) — see that package's doc: an unhardened
// identity fails this handshake silently in the worst case (QUIC/TLS
// looks healthy right up until the HELLO never accepts).
func Connect(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (*Session, error) {
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()

	conn, err := transport.Dial(ctx, host, port, trust)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "open control stream failed")
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
	return session, nil
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
	return s.control.Call(procedure, realm, payload, deadlineMs, id, timeout)
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

// Close sends a signed GOODBYE and closes the underlying QUIC
// connection, matching macula_peering_conn.erl's connected -> draining
// transition (minus the drain-timeout bookkeeping, since this module
// isn't holding a supervisor to clean up).
func (s *Session) Close(reason string, detail *string, id identity.KeyPair) error {
	goodbye := frame.Sign(frame.Goodbye(reason, detail), id)
	_ = s.control.SendFrame(goodbye) // best-effort -- the connection is closing regardless
	return s.conn.CloseWithError(0, reason)
}
