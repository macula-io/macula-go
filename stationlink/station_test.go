package stationlink

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/transport"
)

// testStation is an in-process macula station for one client connection: a
// QUIC listener with a self-signed ML-DSA-87 leaf on macula-pqc's groups,
// macula-go's station side of the handshake, and after HELLO the control stream
// the test drives by hand. startTestStation's is a pre-v5 station: it answers a
// v5 CONNECT with unsupported_version, as a station before macula 13.2.0 does,
// and keeps accepting until one handshake completes, so a client's v4 fallback
// reaches it. startTestStationV5's also answers v5.
type testStation struct {
	t       *testing.T
	profile profile.Profile
	key     *identity.NodeKey
	nodeID  [32]byte
	leaf    []byte
	binding identity.SignedTBS
	host    string
	port    uint16

	// refuse makes the HELLO a refusal with this code.
	refuse handshake.RefusalCode
	// v5 answers handshake v5 too, with the connection's exporter and the
	// station's identity key.
	v5 bool

	mu         sync.Mutex
	client     handshake.Client
	refused    int // handshakes refused before one completed
	connection [48]byte
	stream     *quic.Stream
	writer     *frameWriter
	received   chan []byte
	accepted   chan struct{}
}

var stationKeys sync.Map // profile -> *identity.NodeKey, shared: an RSA-4096 half takes seconds

func sharedIdentityKey(t *testing.T, p profile.Profile, name string) *identity.NodeKey {
	t.Helper()
	if k, ok := stationKeys.Load(string(p) + name); ok {
		return k.(*identity.NodeKey)
	}
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		t.Fatalf("identity key: %v", err)
	}
	actual, _ := stationKeys.LoadOrStore(string(p)+name, key)
	return actual.(*identity.NodeKey)
}

func startTestStation(t *testing.T, p profile.Profile, refuse handshake.RefusalCode) *testStation {
	t.Helper()
	return startStation(t, p, "station", false, refuse)
}

// startTestStationV5 is a station that answers v5, with an identity of its own
// under keyName: a client that completed v5 with a node_id refuses it on v4.
func startTestStationV5(t *testing.T, p profile.Profile, keyName string) *testStation {
	t.Helper()
	return startStation(t, p, keyName, true, "")
}

func startStation(t *testing.T, p profile.Profile, keyName string, v5 bool, refuse handshake.RefusalCode) *testStation {
	t.Helper()
	key := sharedIdentityKey(t, p, keyName)
	tlsKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("TLS key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "station"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, tlsKey.Public(), tlsKey)
	if err != nil {
		t.Fatalf("leaf: %v", err)
	}
	now := time.Now().UnixMilli()
	binding, err := identity.TLSBinding(key, leaf, now, now+7*24*3_600_000)
	if err != nil {
		t.Fatalf("TLS binding: %v", err)
	}
	nodeID, err := key.NodeID()
	if err != nil {
		t.Fatalf("node id: %v", err)
	}
	config := &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: tlsKey}},
		CurvePreferences: transport.KeyExchangeGroups,
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{transport.ALPN},
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", config, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := &testStation{t: t, profile: p, key: key, nodeID: nodeID, leaf: leaf, binding: binding,
		host: host, port: uint16(port), refuse: refuse, v5: v5,
		received: make(chan []byte, 64), accepted: make(chan struct{})}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go s.serve(ctx, listener)
	return s
}

func (s *testStation) target() transport.Target {
	return transport.Target{Host: s.host, Port: s.port, Profile: s.profile, ExpectedNodeID: s.nodeID}
}

// serve accepts connections until one handshake completes, then hands every
// frame that client sends to received.
func (s *testStation) serve(ctx context.Context, listener *quic.Listener) {
	for {
		conn, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		if s.handshaken(ctx, conn) {
			return
		}
		s.mu.Lock()
		s.refused++
		s.mu.Unlock()
	}
}

// handshaken runs the station's side of the handshake on conn and, when it
// completes, serves the client's frames; it reports whether it completed.
func (s *testStation) handshaken(ctx context.Context, conn *quic.Conn) bool {
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return false
	}
	reader, writer := frameReader{r: stream}, &frameWriter{w: stream}
	opener, err := reader.read(HandshakeFrameBytes)
	if err != nil || handshake.ReadOpener(opener) != nil {
		return false
	}
	now := time.Now().UnixMilli()
	status, err := identity.StatusStatement(s.key, s.binding, now, now+3_600_000)
	if err != nil {
		s.t.Errorf("station: status statement: %v", err)
		return false
	}
	challenge, err := handshake.Challenge(handshake.StationMaterial{
		Profile: s.profile, IdentityKey: s.key.PublicKey(), TLSBinding: s.binding, TLSStatus: status})
	if err != nil {
		s.t.Errorf("station: challenge: %v", err)
		return false
	}
	if err := writer.write(challenge, HandshakeFrameBytes); err != nil {
		return false
	}
	connect, err := reader.read(HandshakeFrameBytes)
	if err != nil {
		return false
	}
	session := handshake.StationSession{
		Profile: s.profile, Challenge: challenge, Leaf: s.leaf, PuzzleDifficulty: identity.PuzzleDifficulty,
		PuzzleMode: handshake.PuzzleModeEnforce, Capabilities: 1, NowMs: time.Now().UnixMilli()}
	if s.v5 {
		state := conn.ConnectionState().TLS
		session.Export = state.ExportKeyingMaterial
		session.SignSessionProof = func(_ [32]byte, message []byte) ([]byte, error) { return s.key.Sign(message) }
	}
	client, hello, err := handshake.AcceptConnect(connect, session)
	if s.refuse != "" {
		hello = refusedHello(s.refuse)
	}
	if writer.write(hello, HandshakeFrameBytes) != nil || err != nil || s.refuse != "" {
		_ = stream.Close()
		time.Sleep(50 * time.Millisecond)
		_ = conn.CloseWithError(0, "refused")
		return false
	}
	s.mu.Lock()
	s.client, s.connection, s.stream, s.writer = client, sha512.Sum384(challenge), stream, writer
	s.mu.Unlock()
	close(s.accepted)
	for {
		frame, err := reader.read(MaxFrameBytes)
		if err != nil {
			close(s.received)
			return true
		}
		s.received <- frame
	}
}

// refusedHello is a HELLO refusing with code, as a station sends it.
func refusedHello(code handshake.RefusalCode) []byte {
	return cbor.Encode(cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(handshake.Version)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text("hello")},
		{Key: cbor.Text("accepted"), Val: cbor.Int(0)},
		{Key: cbor.Text("refusal_code"), Val: cbor.Text(string(code))},
		{Key: cbor.Text("capabilities"), Val: cbor.Uint64(1)},
	}))
}

// waitAccepted blocks until the handshake completed on the station's side.
func (s *testStation) waitAccepted() {
	s.t.Helper()
	select {
	case <-s.accepted:
	case <-time.After(10 * time.Second):
		s.t.Fatal("the station never accepted the client")
	}
}

// next is the next frame the client sent after HELLO, as CBOR bytes.
func (s *testStation) next() []byte {
	s.t.Helper()
	select {
	case frame, ok := <-s.received:
		if !ok {
			s.t.Fatal("the client's stream ended")
		}
		return frame
	case <-time.After(10 * time.Second):
		s.t.Fatal("no frame from the client")
		return nil
	}
}

// send writes one frame, as CBOR bytes, to the client.
func (s *testStation) send(frame []byte) {
	s.t.Helper()
	s.mu.Lock()
	writer := s.writer
	s.mu.Unlock()
	if err := writer.write(frame, MaxFrameBytes); err != nil {
		s.t.Fatalf("send: %v", err)
	}
}

// answerCalls answers every CALL the client sends with what answer returns for
// its verified request (a signed RESULT, ERROR or relay error), or nothing when
// it returns an empty value; any other frame goes to others.
func (s *testStation) answerCalls(answer func(frame.VerifiedRequest) (cbor.Value, bool)) (others chan []byte) {
	s.t.Helper()
	s.waitAccepted()
	others = make(chan []byte, 64)
	go func() {
		for raw := range s.received {
			v, err := cbor.Decode(raw)
			if err != nil {
				continue
			}
			if name, _ := fieldOfTest(v, "frame_type").AsText(); name != "call" {
				others <- raw
				continue
			}
			request, err := frame.VerifyRequest(v, s.profile)
			if err != nil {
				s.t.Errorf("station: the client's CALL does not verify: %v", err)
				continue
			}
			if reply, ok := answer(request); ok {
				s.mu.Lock()
				writer := s.writer
				s.mu.Unlock()
				_ = writer.write(cbor.Encode(reply), MaxFrameBytes)
			}
		}
		close(others)
	}()
	return others
}

func fieldOfTest(v cbor.Value, name string) cbor.Value {
	entries, _ := v.AsMap()
	for _, e := range entries {
		if k, _ := e.Key.AsText(); k == name {
			return e.Val
		}
	}
	return cbor.Null()
}
