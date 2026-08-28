// Package connection implements the CONNECT/HELLO handshake and the
// Session it produces — the control-stream lifecycle from
// plans/PLAN_WIRE_PROTOCOL.md §3.
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

// readChunkSize is how much is read per Stream.Read call while
// accumulating a frame.
const readChunkSize = 4096

// Session is a handshaked connection to a macula-station.
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
	// Stream.Read doesn't take a context; wire the same handshake
	// deadline onto the stream directly so a station that never replies
	// doesn't block this call forever.
	if deadline, ok := ctx.Deadline(); ok {
		if err := control.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("connection: set read deadline: %w", err)
		}
	}

	puzzleEvidence := id.PuzzleEvidence()
	spec := frame.NewConnectSpec(id.NodeID(), puzzleEvidence[:])
	connectFrame := frame.Sign(frame.Connect(spec), id)
	encoded, err := frame.Encode(connectFrame)
	if err != nil {
		return nil, fmt.Errorf("connection: encode CONNECT: %w", err)
	}
	if _, err := control.Write(encoded); err != nil {
		return nil, fmt.Errorf("connection: send CONNECT: %w", err)
	}

	helloValue, leftover, err := readOneFrame(control)
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

	return &Session{conn: conn, control: control, buf: leftover, Station: station}, nil
}

// readOneFrame reads from stream until one complete frame has decoded,
// returning it along with any leftover bytes already read that belong
// to the next frame — the handshake-only counterpart to a
// post-handshake ReadFrame that would carry the buffer forward across
// calls (not yet built; every current caller only needs the one HELLO).
// Relies on the stream's own read deadline (set by the caller) to bound
// how long this blocks — Stream.Read doesn't take a context directly.
func readOneFrame(stream *quic.Stream) (cbor.Value, []byte, error) {
	var buf []byte
	chunk := make([]byte, readChunkSize)
	for {
		decoded, err := frame.Decode(buf)
		if err != nil {
			return cbor.Value{}, nil, fmt.Errorf("connection: decode: %w", err)
		}
		if decoded.Complete {
			return decoded.Frame, buf[decoded.Consumed:], nil
		}

		n, err := stream.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			return cbor.Value{}, nil, fmt.Errorf("connection: read control stream: %w", err)
		}
	}
}

// RemoteAddr is the address this session's connection is with.
func (s *Session) RemoteAddr() string {
	return s.conn.RemoteAddr().String()
}

// Close closes the underlying QUIC connection.
func (s *Session) Close() error {
	return s.conn.CloseWithError(0, "closing")
}
