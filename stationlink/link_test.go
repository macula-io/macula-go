package stationlink

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

var profiles = []profile.Profile{profile.PQPure, profile.PQHybrid}

// clientFor is a client's identity key and a statement issuer on a clock the
// test can move.
type clientFor struct {
	key    *identity.NodeKey
	issuer *identity.StatementIssuer
	nowMs  *atomic.Int64
}

func newClient(t *testing.T, p profile.Profile) clientFor {
	t.Helper()
	key := sharedIdentityKey(t, p, "client")
	now := &atomic.Int64{}
	now.Store(time.Now().UnixMilli())
	issuer, err := identity.NewStatementIssuer(key, now.Load)
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	return clientFor{key: key, issuer: issuer, nowMs: now}
}

func dial(t *testing.T, s *testStation, c clientFor) (*Link, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	link, err := Dial(ctx, Config{Target: s.target(), IdentityKey: c.key, Issuer: c.issuer})
	if err == nil {
		t.Cleanup(func() { _ = link.Close("test_done") })
	}
	return link, err
}

func waitDone(t *testing.T, link *Link) error {
	t.Helper()
	select {
	case <-link.Done():
		return link.Err()
	case <-time.After(10 * time.Second):
		t.Fatal("the link did not end")
		return nil
	}
}

func decodeFrame(t *testing.T, b []byte) cbor.Value {
	t.Helper()
	v, err := cbor.Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return v
}

func frameField(v cbor.Value, name string) cbor.Value {
	entries, _ := v.AsMap()
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k == name {
			return e.Val
		}
	}
	return cbor.Null()
}

// A link completes the v4 handshake with a station of either profile: the
// station accepts the client's node_id and is handed an empty endorsement, and
// the link knows the station it reached.
func TestDialHandshakesWithAStationOfEachProfile(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			s := startTestStation(t, p, "")
			c := newClient(t, p)
			link, err := dial(t, s, c)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			s.waitAccepted()
			clientID, _ := c.key.NodeID()
			if s.client.NodeID != clientID || len(s.client.MemberEndorsement) != 0 {
				t.Errorf("the station accepted node_id %x with endorsement %x", s.client.NodeID, s.client.MemberEndorsement)
			}
			if link.StationNodeID() != s.nodeID || link.StationCapabilities() != 1 {
				t.Errorf("the link reached %x with capabilities %d", link.StationNodeID(), link.StationCapabilities())
			}
		})
	}
}

// A station that is not the one the target names is refused before the
// client signs anything, and a refused HELLO is reported with its code.
func TestDialRefusesTheWrongStationAndReportsARefusal(t *testing.T) {
	s := startTestStation(t, profile.PQPure, "")
	c := newClient(t, profile.PQPure)
	target := s.target()
	target.ExpectedNodeID[0] ^= 1
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := Dial(ctx, Config{Target: target, IdentityKey: c.key, Issuer: c.issuer}); !errors.Is(err, handshake.ErrPeerIdentityMismatch) {
		t.Errorf("another station: %v, want ErrPeerIdentityMismatch", err)
	}
	refusing := startTestStation(t, profile.PQPure, handshake.RefusalPuzzleInvalid)
	_, err := dial(t, refusing, c)
	var refused *handshake.RefusedError
	if !errors.As(err, &refused) || refused.Code != handshake.RefusalPuzzleInvalid {
		t.Errorf("a refusing station: %v, want a refusal with puzzle_invalid", err)
	}
}

// At each reissue of the client's statement the link sends it as a STATUS,
// which the station verifies against the client's CONNECT binding.
func TestTheLinkSendsAStatusAtEachReissue(t *testing.T) {
	s := startTestStation(t, profile.PQPure, "")
	c := newClient(t, profile.PQPure)
	if _, err := dial(t, s, c); err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	c.nowMs.Add(16 * 60_000)
	if err := c.issuer.Tick(); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	status := s.next()
	expires, err := handshake.ReadStatus(status, handshake.Peer{
		Profile: profile.PQPure, IdentityKey: s.client.IdentityKey, Binding: s.client.ConnectBinding, NowMs: c.nowMs.Load()})
	if err != nil || expires <= c.nowMs.Load() {
		t.Errorf("the STATUS: expires %d, %v", expires, err)
	}
}

// When the station's statement lapses past the grace, the link ends.
func TestALapsedStationStatusEndsTheLink(t *testing.T) {
	restore := statusGrace
	statusGrace = 50 * time.Millisecond
	t.Cleanup(func() { statusGrace = restore })
	s := startTestStation(t, profile.PQPure, "")
	c := newClient(t, profile.PQPure)
	link, err := dial(t, s, c)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	s.waitAccepted()
	now := time.Now().UnixMilli()
	statement, err := identity.StatusStatement(s.key, s.binding, now, now+100)
	if err != nil {
		t.Fatalf("statement: %v", err)
	}
	s.send(handshake.StatusFrame(statement))
	if err := waitDone(t, link); !errors.Is(err, ErrStatusExpired) {
		t.Errorf("the link ended with %v, want ErrStatusExpired", err)
	}
}

// Close sends a GOODBYE, neighbour-signed at seq 0 in pq_hybrid and plain in
// pq_pure, and ends the link.
func TestCloseSendsAGoodbye(t *testing.T) {
	for _, p := range profiles {
		t.Run(string(p), func(t *testing.T) {
			s := startTestStation(t, p, "")
			c := newClient(t, p)
			link, err := dial(t, s, c)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			s.waitAccepted()
			if err := link.Close("client_stop"); err != nil {
				t.Fatalf("Close: %v", err)
			}
			opened, err := frame.VerifyNeighbour(decodeFrame(t, s.next()), frame.NeighbourPeer{
				Profile: p, PeerKey: s.client.IdentityKey, Connection: s.connection, Seq: 0})
			if err != nil {
				t.Fatalf("the GOODBYE: %v", err)
			}
			if reason, _ := frameField(opened, "reason").AsText(); reason != "client_stop" {
				t.Errorf("GOODBYE reason %q", reason)
			}
			<-link.Done()
		})
	}
}

// A station's GOODBYE, neighbour-signed at seq 0, ends the link with its
// reason; one at the wrong seq ends it as malformed.
func TestAStationGoodbyeEndsTheLink(t *testing.T) {
	for _, seq := range []uint64{0, 1} {
		s := startTestStation(t, profile.PQHybrid, "")
		c := newClient(t, profile.PQHybrid)
		link, err := dial(t, s, c)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		s.waitAccepted()
		goodbye, err := frame.GoodbyeFrame("normal", nil)
		if err != nil {
			t.Fatalf("GoodbyeFrame: %v", err)
		}
		signed, err := frame.SignNeighbour(goodbye, s.key, frame.NeighbourLink{Connection: s.connection, Seq: seq})
		if err != nil {
			t.Fatalf("SignNeighbour: %v", err)
		}
		s.send(cbor.Encode(signed))
		err = waitDone(t, link)
		var bye *GoodbyeError
		switch seq {
		case 0:
			if !errors.As(err, &bye) || bye.Reason != "normal" {
				t.Errorf("seq 0: the link ended with %v, want the station's goodbye", err)
			}
		default:
			if !errors.Is(err, frame.ErrMalformedFrame) {
				t.Errorf("seq %d: the link ended with %v, want ErrMalformedFrame", seq, err)
			}
		}
	}
}
