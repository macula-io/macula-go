package pool

import (
	"context"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// sessionLike is the slice of *connection.Session a link actor needs —
// deliberately an interface, not the concrete type, so a test can supply
// an in-memory fake and exercise respawn/replay/dedup deterministically
// without a live QUIC connection (the same reasoning
// connection/serve_ucan_test.go already applies at a smaller scale by
// passing a nil *Session into pure dispatch-logic tests). *connection.Session
// satisfies this today with no changes needed beyond RecvAny/SendAny
// (connection/raw.go) — every method below already existed.
type sessionLike interface {
	RecvAny(deadline time.Time) (cbor.Value, error)
	SendAny(v cbor.Value) error
	Done() <-chan struct{}
	Close(reason string, detail *string, id identity.KeyPair) error
	RemoteAddr() string
}

// dialResult is what dialing one seed/target produces: the live session,
// plus the peer's own node id (read synchronously off the already-
// verified HELLO — connection.Session.Station.NodeID — no probe round
// trip needed, unlike macula_client.erl's own async safe_peer_node_id).
type dialResult struct {
	session sessionLike
	nodeID  []byte
	remote  string
}

// dialFunc dials one link target. The pool's default is dialSession
// (below), wrapping connection.Connect; tests inject a fake.
type dialFunc func(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (dialResult, error)

func dialSession(ctx context.Context, host string, port uint16, trust transport.Trust, id identity.KeyPair) (dialResult, error) {
	session, err := connection.Connect(ctx, host, port, trust, id)
	if err != nil {
		return dialResult{}, err
	}
	return dialResult{session: session, nodeID: session.Station.NodeID, remote: session.RemoteAddr()}, nil
}
