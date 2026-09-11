package pool

import (
	"context"
	"time"

	"github.com/macula-io/macula-go/connection"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/transport"
)

// sessionLike is the slice of *connection.Session a link needs, as an
// interface so a test can supply an in-memory fake and exercise respawn,
// replay, dedup and fall-through deterministically without a live QUIC
// connection.
type sessionLike interface {
	LinkCall(spec frame.CallSpec, id identity.KeyPair, timeout time.Duration) (frame.CallResponse, error)
	Publish(spec frame.PublishSpec, id identity.KeyPair) error
	Subscribe(spec frame.SubscribeSpec, id identity.KeyPair) (subscription, error)
	Done() <-chan struct{}
	Err() error
	Close(reason string, detail *string, id identity.KeyPair) error
	RemoteAddr() string
}

// subscription is the slice of *connection.Subscription a link needs.
type subscription interface {
	Recv(timeout time.Duration) (frame.EventInfo, error)
	Close() error
}

// liveSession is a *connection.Session as a sessionLike; only Subscribe
// differs, returning the subscription interface.
type liveSession struct{ *connection.Session }

func (s liveSession) Subscribe(spec frame.SubscribeSpec, id identity.KeyPair) (subscription, error) {
	sub, err := s.Session.Subscribe(spec, id)
	if err != nil {
		return nil, err
	}
	return sub, nil
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
	return dialResult{session: liveSession{session}, nodeID: session.Station.NodeID, remote: session.RemoteAddr()}, nil
}
