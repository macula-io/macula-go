// Package connection implements the CONNECT/HELLO handshake, the
// Session it produces, and the control-stream application primitives
// built on top of it (CALL, PUBLISH/SUBSCRIBE/EVENT, ADVERTISE) — see
// plans/PLAN_WIRE_PROTOCOL.md §3, §6.
package connection

import (
	"context"
	"crypto/rand"
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

// readChunkSize is how much is read per Stream.Read call while
// accumulating a frame.
const readChunkSize = 4096

// Session is a handshaked connection to a macula-station: the open
// control stream (CONNECT/HELLO already exchanged) and the station's
// identity as verified by the HELLO frame's own signature.
type Session struct {
	conn    *quic.Conn
	control *quic.Stream
	buf     []byte // leftover bytes already read that belong to the next frame
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

	control, err := conn.OpenStreamSync(ctx)
	if err != nil {
		conn.CloseWithError(0, "open control stream failed")
		return nil, fmt.Errorf("connection: open control stream: %w", err)
	}

	session := &Session{conn: conn, control: control}

	puzzleEvidence := id.PuzzleEvidence()
	spec := frame.NewConnectSpec(id.NodeID(), puzzleEvidence[:])
	connectFrame := frame.Sign(frame.Connect(spec), id)
	if err := session.sendFrame(connectFrame); err != nil {
		return nil, fmt.Errorf("connection: send CONNECT: %w", err)
	}

	deadline, _ := ctx.Deadline()
	helloValue, err := session.recvFrame(deadline)
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

// sendFrame encodes and writes v to the control stream.
func (s *Session) sendFrame(v cbor.Value) error {
	encoded, err := frame.Encode(v)
	if err != nil {
		return fmt.Errorf("connection: encode frame: %w", err)
	}
	if _, err := s.control.Write(encoded); err != nil {
		return fmt.Errorf("connection: write frame: %w", err)
	}
	return nil
}

// recvFrame reads the next complete application frame off the control
// stream, using (and updating) s.buf. deadline bounds the read
// (Stream.Read doesn't take a context directly); a zero deadline means
// no bound.
func (s *Session) recvFrame(deadline time.Time) (cbor.Value, error) {
	if err := s.control.SetReadDeadline(deadline); err != nil {
		return cbor.Value{}, fmt.Errorf("connection: set read deadline: %w", err)
	}
	chunk := make([]byte, readChunkSize)
	for {
		decoded, err := frame.Decode(s.buf)
		if err != nil {
			return cbor.Value{}, fmt.Errorf("connection: decode: %w", err)
		}
		if decoded.Complete {
			s.buf = s.buf[decoded.Consumed:]
			return decoded.Frame, nil
		}

		n, err := s.control.Read(chunk)
		if n > 0 {
			s.buf = append(s.buf, chunk[:n]...)
		}
		if err != nil {
			return cbor.Value{}, fmt.Errorf("connection: read control stream: %w", err)
		}
	}
}

// Call sends a signed CALL for procedure and waits for the matching
// RESULT or ERROR, correlated by call_id.
//
// Known v1 limitation (control stream only): any frame that arrives
// before the match (e.g. an EVENT from an active Subscribe) is
// discarded, not queued or dispatched elsewhere — correct for a client
// doing one thing at a time on the control stream, not yet correct for
// Call and Publish/Subscribe used concurrently on it.
func (s *Session) Call(procedure string, realm []byte, payload cbor.Value, deadlineMs int64, id identity.KeyPair, timeout time.Duration) (frame.CallResponse, error) {
	callID := make([]byte, 16)
	if _, err := rand.Read(callID); err != nil {
		return frame.CallResponse{}, fmt.Errorf("connection: generate call_id: %w", err)
	}
	spec := frame.NewCallSpec(callID, procedure, realm, payload, deadlineMs, id.NodeID())
	signed := frame.Sign(frame.Call(spec), id)
	if err := s.sendFrame(signed); err != nil {
		return frame.CallResponse{}, err
	}

	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			return frame.CallResponse{}, fmt.Errorf("connection: call: timed out waiting for a response")
		}
		value, err := s.recvFrame(deadline)
		if err != nil {
			return frame.CallResponse{}, err
		}
		gotID, ok := frame.FrameCallID(value)
		if !ok || string(gotID) != string(callID) {
			continue // not ours -- see this method's doc on the v1 limitation
		}
		response, err := frame.ParseCallResponse(value)
		if err != nil {
			// Matching call_id but not a result/error shape: keep
			// waiting rather than erroring, since nothing else in the
			// protocol is expected to carry this call's id.
			continue
		}
		return response, nil
	}
}

// Publish sends a signed PUBLISH. Fire-and-forget — no reply is
// expected on the wire; a subscriber (this session included, if
// subscribed to the same topic/realm) receives an EVENT asynchronously,
// read via RecvEvent.
func (s *Session) Publish(spec frame.PublishSpec, id identity.KeyPair) error {
	return s.sendFrame(frame.Sign(frame.Publish(spec), id))
}

// Subscribe sends a signed SUBSCRIBE. Fire-and-forget.
func (s *Session) Subscribe(spec frame.SubscribeSpec, id identity.KeyPair) error {
	return s.sendFrame(frame.Sign(frame.Subscribe(spec), id))
}

// Unsubscribe sends a signed UNSUBSCRIBE. Fire-and-forget.
func (s *Session) Unsubscribe(spec frame.UnsubscribeSpec, id identity.KeyPair) error {
	return s.sendFrame(frame.Sign(frame.Unsubscribe(spec), id))
}

// Advertise sends a signed ADVERTISE (§6.9) — registers this connection
// as the handler for spec's (realm, procedure). Fire-and-forget on the
// wire; the station then routes inbound CALLs (control stream) back to
// this connection.
func (s *Session) Advertise(spec frame.AdvertiseSpec, id identity.KeyPair) error {
	return s.sendFrame(frame.Sign(frame.Advertise(spec), id))
}

// Unadvertise sends a signed UNADVERTISE. Fire-and-forget.
func (s *Session) Unadvertise(spec frame.UnadvertiseSpec, id identity.KeyPair) error {
	return s.sendFrame(frame.Sign(frame.Unadvertise(spec), id))
}

// RecvEvent reads the next frame and parses it as an EVENT, bounded by
// timeout. Any non-EVENT frame received first is an error, not
// silently skipped — unlike Call's response wait, a caller waiting
// specifically for a pubsub delivery has no reason to expect anything
// else to legitimately arrive first.
func (s *Session) RecvEvent(timeout time.Duration) (frame.EventInfo, error) {
	value, err := s.recvFrame(time.Now().Add(timeout))
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
	_ = s.sendFrame(goodbye) // best-effort -- the connection is closing regardless
	return s.conn.CloseWithError(0, reason)
}
