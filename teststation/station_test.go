package teststation

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
	"github.com/quic-go/quic-go/qlogwriter"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/stationlink"
	"github.com/macula-io/macula-go/transport"
)

func dial(t *testing.T, s *Station, name string) *stationlink.Link {
	t.Helper()
	key := Key(t, s.Profile, name)
	issuer, err := identity.NewStatementIssuer(key, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := stationlink.Dial(ctx, stationlink.Config{Target: s.Target(), IdentityKey: key, Issuer: issuer})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = link.Close("test_done") })
	s.WaitAccepted()
	return link
}

// The station answers as one does: its own endpoint is in its DHT, ping is its
// relay error, an unadvertised procedure is unknown_next_peer, and a PUBLISH
// comes back to its subscriber as an EVENT.
func TestTheStationAnswersAsAStationDoes(t *testing.T) {
	s := Start(t, profile.PQPure, "smoke")
	link := dial(t, s, "smoke client")
	ctx := t.Context()
	endpoint, err := link.FindRecord(ctx, record.StationEndpointKey(s.NodeID))
	if err != nil || endpoint.Record().KeyID != s.NodeID {
		t.Errorf("its endpoint: %v", err)
	}
	var relay *stationlink.RelayError
	if _, err := link.Call(ctx, stationlink.Call{Procedure: "_macula.ping", Payload: cbor.Map(nil)}); !errors.As(err, &relay) || relay.Code != "unknown_next_peer" {
		t.Errorf("ping: %v", err)
	}
	if _, err := link.Call(ctx, stationlink.Call{Realm: [32]byte{1}, Procedure: "org/nothing", Target: [32]byte{2}, Payload: cbor.Map(nil), Clear: true}); !errors.As(err, &relay) || relay.Code != "unknown_next_peer" {
		t.Errorf("an unadvertised procedure: %v", err)
	}
	sub, err := link.Subscribe([32]byte{1}, "org/topic")
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := link.Publish(stationlink.Publication{Realm: [32]byte{1}, Topic: "org/topic", Payload: cbor.Text("hi")}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	select {
	case event := <-sub.Events():
		if text, _ := event.Payload.AsText(); text != "hi" {
			t.Errorf("event %q", text)
		}
	case <-time.After(5 * time.Second):
		t.Error("no event")
	}
}

// Drop ends a client's connection.
func TestDropEndsTheClientsLink(t *testing.T) {
	s := Start(t, profile.PQPure, "drop")
	link := dial(t, s, "drop client")
	s.Drop(link.NodeID())
	select {
	case <-link.Done():
	case <-time.After(5 * time.Second):
		t.Error("the link outlived its connection")
	}
}

// The station keeps a live station's connection lifetime: it advertises a
// 300 s idle timeout, not quic-go's 30 s, and sends a keepalive PING after
// 15 s of quiet. The client here asks for an hour and sends no keepalive of
// its own, so both values seen on the wire are the station's.
func TestTheStationKeepsALiveStationsIdleTimeoutAndKeepalive(t *testing.T) {
	s := Start(t, profile.PQPure, "idle")
	seen := &transportSeen{received: time.Now(), pinged: make(chan struct{}, 1)}
	conn, err := quic.DialAddr(t.Context(), net.JoinHostPort(s.Host, strconv.Itoa(int(s.Port))), &tls.Config{
		InsecureSkipVerify: true, CurvePreferences: maculaPQCGroups, MinVersion: tls.VersionTLS13,
		NextProtos: []string{transport.ALPN}, SessionTicketsDisabled: true,
	}, &quic.Config{MaxIdleTimeout: time.Hour, Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace { return seen }})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "") }()
	if idle := seen.idleTimeout(); idle != transport.IdleTimeout {
		t.Errorf("the station advertises an idle timeout of %v, want %v", idle, transport.IdleTimeout)
	}
	select {
	case <-seen.pinged:
	case <-time.After(transport.KeepAlivePeriod + 5*time.Second):
		t.Errorf("no keepalive PING from the station within %v", transport.KeepAlivePeriod+5*time.Second)
	}
}

// transportSeen records, from a client's qlog, the idle timeout its peer
// advertised and whether the peer has sent a keepalive: a PING after at least
// a second short of KeepAlivePeriod with nothing received, which the
// handshake's own PINGs never are.
type transportSeen struct {
	mu       sync.Mutex
	idle     time.Duration
	received time.Time
	pinged   chan struct{}
}

func (s *transportSeen) AddProducer() qlogwriter.Recorder { return s }
func (s *transportSeen) SupportsSchemas(string) bool      { return true }
func (s *transportSeen) Close() error                     { return nil }

func (s *transportSeen) RecordEvent(event qlogwriter.Event) {
	switch e := event.(type) {
	case qlog.ParametersSet:
		if e.Initiator == qlog.InitiatorRemote {
			s.mu.Lock()
			s.idle = e.MaxIdleTimeout
			s.mu.Unlock()
		}
	case qlog.PacketReceived:
		s.mu.Lock()
		quiet := time.Since(s.received)
		s.received = time.Now()
		s.mu.Unlock()
		if quiet < transport.KeepAlivePeriod-time.Second || !carriesPing(e.Frames) {
			return
		}
		select {
		case s.pinged <- struct{}{}:
		default:
		}
	}
}

func carriesPing(frames []qlog.Frame) bool {
	for _, f := range frames {
		if _, ok := f.Frame.(*qlog.PingFrame); ok {
			return true
		}
	}
	return false
}

func (s *transportSeen) idleTimeout() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.idle
}
