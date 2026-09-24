// Package teststation is an in-process macula 12 station for tests of the
// clients built on macula-go, in Go or through its bindings: a QUIC listener with an ML-DSA-87 leaf on
// macula-pqc's groups that accepts any number of client connections, runs the
// station's side of the v4 handshake on each, and then does what a station
// does with their frames: answers _macula.ping and the _dht.* procedures from
// an in-memory DHT, routes a CALL to the connection that advertised its
// procedure and the reply back to the caller, and delivers each PUBLISH as an
// EVENT to every connection subscribed to its realm and topic.
//
// It keeps a station's contract, not its implementation: records are verified
// on put, a CALL for an unadvertised procedure gets the station's signed
// relay error unknown_next_peer, and a renewed ADVERTISE replaces the one
// before it. Tests can drop a client's connection to exercise reconnects.
package teststation

import (
	"context"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
	"github.com/macula-io/macula-go/record"
	"github.com/macula-io/macula-go/transport"
)

// The frame caps of a control stream, as stationlink holds them.
const (
	handshakeFrameBytes = 64 * 1024
	maxFrameBytes       = 16 * 1024 * 1024
)

// T is what the station reports its failures to and registers its cleanup
// with: a *testing.T, or, outside a test (a helper process serving another
// language's tests), anything with these methods.
type T interface {
	Helper()
	Errorf(format string, args ...any)
	Fatalf(format string, args ...any)
	Cleanup(func())
}

// Station is a running test station.
type Station struct {
	t       T
	Profile profile.Profile
	Key     *identity.NodeKey
	NodeID  [32]byte
	Host    string
	Port    uint16
	leaf    []byte
	binding identity.SignedTBS

	mu       sync.Mutex
	conns    map[[32]byte]*conn // by the client's node_id; a reconnect replaces
	routes   map[routeKey]*conn // the connection that advertised; gone with it
	pending  map[[16]byte]*conn // request_id -> the caller's connection
	dht      *dht
	accepted chan [32]byte
	listener *quic.Listener
	// relayed counts the dedicated streams relayed now, each until both its
	// directions have finished: a client that never releases a stream keeps
	// it counted.
	relayed int
	stopped bool
}

type routeKey struct {
	realm     [32]byte
	procedure string
}

// dht is a station's record store; stations that share one stand in for a
// DHT replicating between them.
type dht struct {
	mu      sync.Mutex
	records map[slot][]byte
}

type slot struct {
	key    [32]byte
	signer [32]byte
}

type conn struct {
	nodeID     [32]byte
	qconn      *quic.Conn
	writer     *writer
	client     handshake.Client
	connection [48]byte
	recvSeq    uint64
	topics     map[routeKey]bool
}

var keys sync.Map // name+profile -> *identity.NodeKey: puzzle-solved keys take a while

// Key is a puzzle-solved identity key for name in profile p, the same one each
// time it is asked for in a test binary.
func Key(t T, p profile.Profile, name string) *identity.NodeKey {
	t.Helper()
	if k, ok := keys.Load(string(p) + name); ok {
		return k.(*identity.NodeKey)
	}
	key, err := identity.GenerateIdentityKey(p, identity.PuzzleDifficulty)
	if err != nil {
		t.Fatalf("teststation: identity key: %v", err)
	}
	actual, _ := keys.LoadOrStore(string(p)+name, key)
	return actual.(*identity.NodeKey)
}

// Start starts a station named name, stopped when the test ends. Its own
// station_endpoint record is in its DHT.
func Start(t T, p profile.Profile, name string) *Station {
	t.Helper()
	key := Key(t, p, "station "+name)
	tlsKey, err := mldsa.GenerateKey(mldsa.MLDSA87())
	if err != nil {
		t.Fatalf("teststation: TLS key: %v", err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leaf, err := x509.CreateCertificate(rand.Reader, template, template, tlsKey.Public(), tlsKey)
	if err != nil {
		t.Fatalf("teststation: leaf: %v", err)
	}
	now := time.Now().UnixMilli()
	binding, err := identity.TLSBinding(key, leaf, now, now+6*24*3_600_000)
	if err != nil {
		t.Fatalf("teststation: TLS binding: %v", err)
	}
	nodeID, _ := key.NodeID()
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates:     []tls.Certificate{{Certificate: [][]byte{leaf}, PrivateKey: tlsKey}},
		CurvePreferences: transport.KeyExchangeGroups, MinVersion: tls.VersionTLS13, NextProtos: []string{transport.ALPN},
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("teststation: listen: %v", err)
	}
	host, portText, _ := net.SplitHostPort(listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	s := &Station{t: t, Profile: p, Key: key, NodeID: nodeID, Host: host, Port: uint16(port), leaf: leaf, binding: binding,
		conns: map[[32]byte]*conn{}, routes: map[routeKey]*conn{}, pending: map[[16]byte]*conn{},
		dht: &dht{records: map[slot][]byte{}}, accepted: make(chan [32]byte, 64), listener: listener}
	s.putOwnEndpoint()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		s.Stop()
	})
	go s.accept(ctx)
	return s
}

// Target is the station as a pinned dial target.
func (s *Station) Target() transport.Target {
	return transport.Target{Host: s.Host, Port: s.Port, Profile: s.Profile, ExpectedNodeID: s.NodeID}
}

// Stop closes the listener and every connection. A stopped station accepts
// no more.
func (s *Station) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	conns := s.conns
	s.conns = map[[32]byte]*conn{}
	s.mu.Unlock()
	_ = s.listener.Close()
	for _, c := range conns {
		_ = c.qconn.CloseWithError(0, "station stopped")
	}
}

// WaitAccepted blocks until a client connection is accepted, and returns its
// node_id.
func (s *Station) WaitAccepted() [32]byte {
	s.t.Helper()
	select {
	case id := <-s.accepted:
		return id
	case <-time.After(15 * time.Second):
		s.t.Fatalf("teststation: no client was accepted")
		return [32]byte{}
	}
}

// Drop closes the connection of the client node_id, as a station restart or a
// network failure would.
func (s *Station) Drop(nodeID [32]byte) {
	s.mu.Lock()
	c := s.conns[nodeID]
	s.mu.Unlock()
	if c != nil {
		s.forget(c)
		_ = c.qconn.CloseWithError(0, "dropped")
	}
}

// Connected reports whether the client node_id holds a connection.
func (s *Station) Connected(nodeID [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, held := s.conns[nodeID]
	return held
}

// Advertised reports whether a live connection advertised procedure in realm
// here. A reconnecting node advertises again on its new connection.
func (s *Station) Advertised(realm [32]byte, procedure string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.routes[routeKey{realm, procedure}] != nil
}

// Subscribed reports whether the client node_id's connection is subscribed to
// topic in realm.
func (s *Station) Subscribed(nodeID, realm [32]byte, topic string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.conns[nodeID]
	return c != nil && c.topics[routeKey{realm, topic}]
}

// ShareDHT makes the stations hold one record store, as a DHT replicating
// between them would: a record put at one is found at every other. Their
// records so far are kept.
func ShareDHT(stations ...*Station) {
	shared := &dht{records: map[slot][]byte{}}
	for _, s := range stations {
		s.mu.Lock()
		s.dht.mu.Lock()
		for sl, wire := range s.dht.records {
			shared.records[sl] = wire
		}
		s.dht.mu.Unlock()
		s.dht = shared
		s.mu.Unlock()
	}
}

// Forge stores wire under key whatever record it is, as a station lying about
// its DHT would answer; it replaces what the key held.
func (s *Station) Forge(key [32]byte, wire []byte) {
	s.mu.Lock()
	d := s.dht
	s.mu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	for sl := range d.records {
		if sl.key == key {
			delete(d.records, sl)
		}
	}
	d.records[slot{key: key}] = wire
}

// Put stores a record's wire bytes in the DHT, as a put_record would, and
// fails the test when it does not verify.
func (s *Station) Put(wire []byte) {
	s.t.Helper()
	if err := s.store(wire); err != nil {
		s.t.Fatalf("teststation: put: %v", err)
	}
}

func (s *Station) putOwnEndpoint() {
	unsigned, err := record.NewStationEndpoint(s.Port, record.StationEndpointOptions{HostAdvertised: []string{s.Host}})
	if err != nil {
		s.t.Fatalf("teststation: endpoint: %v", err)
	}
	signed, err := record.Sign(unsigned, s.Key)
	if err != nil {
		s.t.Fatalf("teststation: endpoint: %v", err)
	}
	wire, err := record.Encode(signed)
	if err != nil {
		s.t.Fatalf("teststation: endpoint: %v", err)
	}
	s.Put(wire)
}

func (s *Station) store(wire []byte) error {
	verified, err := record.Verify(wire, s.Profile, time.Now().UnixMilli())
	if err != nil {
		return err
	}
	key, err := record.StorageKey(verified.Record())
	if err != nil {
		return err
	}
	s.mu.Lock()
	d := s.dht
	s.mu.Unlock()
	d.mu.Lock()
	d.records[slot{key, verified.Record().KeyID}] = wire
	d.mu.Unlock()
	return nil
}

func (s *Station) accept(ctx context.Context) {
	for {
		qconn, err := s.listener.Accept(ctx)
		if err != nil {
			return
		}
		go s.serve(ctx, qconn)
	}
}

// serve runs the station's side of the handshake on one connection, then its
// frames until it ends.
func (s *Station) serve(ctx context.Context, qconn *quic.Conn) {
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		return
	}
	r, w := &reader{r: stream}, &writer{w: stream}
	opener, err := r.read(handshakeFrameBytes)
	if err != nil || handshake.ReadOpener(opener) != nil {
		return
	}
	now := time.Now().UnixMilli()
	status, err := identity.StatusStatement(s.Key, s.binding, now, now+3_600_000)
	if err != nil {
		return
	}
	challenge, err := handshake.Challenge(handshake.StationMaterial{
		Profile: s.Profile, IdentityKey: s.Key.PublicKey(), TLSBinding: s.binding, TLSStatus: status})
	if err != nil || w.write(challenge, handshakeFrameBytes) != nil {
		return
	}
	connect, err := r.read(handshakeFrameBytes)
	if err != nil {
		return
	}
	client, hello, err := handshake.AcceptConnect(connect, handshake.StationSession{
		Profile: s.Profile, Challenge: challenge, Leaf: s.leaf, PuzzleDifficulty: identity.PuzzleDifficulty,
		PuzzleMode: handshake.PuzzleModeEnforce, Capabilities: 1, NowMs: time.Now().UnixMilli()})
	if w.write(hello, handshakeFrameBytes) != nil || err != nil {
		return
	}
	c := &conn{nodeID: client.NodeID, qconn: qconn, writer: w, client: client, connection: sha512.Sum384(challenge),
		topics: map[routeKey]bool{}}
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		_ = qconn.CloseWithError(0, "station stopped")
		return
	}
	previous := s.conns[c.nodeID]
	s.conns[c.nodeID] = c
	s.mu.Unlock()
	if previous != nil {
		_ = previous.qconn.CloseWithError(0, "superseded")
	}
	s.accepted <- c.nodeID
	go s.relayStreams(ctx, c)
	for {
		payload, err := r.read(maxFrameBytes)
		if err != nil {
			s.forget(c)
			return
		}
		s.received(c, payload)
	}
}

// forget drops a connection that ended, unless a reconnect already replaced
// it, and the routes it advertised, as a station sweeps a dead advertiser.
func (s *Station) forget(c *conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[c.nodeID] == c {
		delete(s.conns, c.nodeID)
	}
	for key, advertiser := range s.routes {
		if advertiser == c {
			delete(s.routes, key)
		}
	}
}

func (s *Station) received(c *conn, payload []byte) {
	v, err := cbor.Decode(payload)
	if err != nil {
		return
	}
	frameType, _ := field(v, "frame_type").AsText()
	if frameType == "status" {
		return
	}
	opened, err := frame.VerifyNeighbour(v, frame.NeighbourPeer{Profile: s.Profile, PeerKey: c.client.IdentityKey,
		Connection: c.connection, Seq: c.recvSeq})
	if err != nil {
		s.t.Errorf("teststation: a frame from %x that does not open: %v", c.nodeID[:4], err)
		_ = c.qconn.CloseWithError(1, "malformed")
		return
	}
	if frame.NeighbourSigned(s.Profile, frameType) {
		c.recvSeq++
	}
	switch frameType {
	case "call":
		s.called(c, opened, payload)
	case "result", "error":
		s.replied(payload, opened)
	case "advertise":
		s.advertised(c, opened)
	case "unadvertise":
		s.unadvertised(opened)
	case "subscribe", "unsubscribe":
		s.subscribed(c, opened, frameType == "subscribe")
	case "publish":
		s.published(opened)
	case "goodbye":
		_ = c.qconn.CloseWithError(0, "goodbye")
	}
}

// called answers a station procedure itself, and routes any other CALL to the
// connection that advertised it, or refuses it with unknown_next_peer.
func (s *Station) called(c *conn, v cbor.Value, raw []byte) {
	request, err := frame.VerifyRequest(v, s.Profile)
	if err != nil {
		return
	}
	if request.Target == s.NodeID {
		s.answer(c, request)
		return
	}
	s.mu.Lock()
	provider := s.routes[routeKey{request.Realm, request.Procedure}]
	routed := provider != nil && provider.nodeID == request.Target
	if routed {
		s.pending[request.RequestID] = c
	}
	s.mu.Unlock()
	if !routed {
		s.relayError(c, request, "unknown_next_peer")
		return
	}
	_ = provider.writer.write(raw, maxFrameBytes)
}

func (s *Station) replied(raw []byte, v cbor.Value) {
	id, _, err := frame.ClaimedReplyIDs(v)
	if err != nil {
		return
	}
	s.mu.Lock()
	caller := s.pending[id]
	delete(s.pending, id)
	s.mu.Unlock()
	if caller != nil {
		_ = caller.writer.write(raw, maxFrameBytes)
	}
}

func (s *Station) relayError(c *conn, request frame.VerifiedRequest, code string) {
	reply, err := frame.SignRelayError(frame.RelayErrorSpec{FrameType: "error", Request: request, Code: code}, s.Key)
	if err != nil {
		s.t.Errorf("teststation: relay error: %v", err)
		return
	}
	_ = c.writer.write(cbor.Encode(reply), maxFrameBytes)
}

// answer serves the station's own procedures.
func (s *Station) answer(c *conn, request frame.VerifiedRequest) {
	var result cbor.Value
	switch request.Procedure {
	case "_dht.put_record":
		wire, _ := request.Payload.AsBytes()
		if err := s.store(wire); err != nil {
			s.relayError(c, request, "bad_signature")
			return
		}
		result = cbor.Text("ok")
	case "_dht.find_record":
		found := s.find(func(sl slot, _ []byte) bool { return sl.key == keyOf(request.Payload) })
		if len(found) == 0 {
			result = cbor.Text("not_found")
		} else {
			result = cbor.Bytes(found[0])
		}
	case "_dht.find_records":
		result = list(s.find(func(sl slot, _ []byte) bool { return sl.key == keyOf(request.Payload) }))
	case "_dht.find_records_by_type":
		typeValue, _ := request.Payload.Get("type")
		n, _ := typeValue.AsInt64()
		result = list(s.find(func(_ slot, wire []byte) bool {
			verified, err := record.Verify(wire, s.Profile, time.Now().UnixMilli())
			return err == nil && int64(verified.Record().Type) == n
		}))
	default:
		s.relayError(c, request, "unknown_next_peer")
		return
	}
	reply, err := frame.SignResult(request, result, nil, s.Key)
	if err != nil {
		s.t.Errorf("teststation: result: %v", err)
		return
	}
	_ = c.writer.write(cbor.Encode(reply), maxFrameBytes)
}

func (s *Station) find(match func(slot, []byte) bool) [][]byte {
	s.mu.Lock()
	d := s.dht
	s.mu.Unlock()
	d.mu.Lock()
	defer d.mu.Unlock()
	var found [][]byte
	for sl, wire := range d.records {
		if match(sl, wire) {
			found = append(found, wire)
		}
	}
	return found
}

// advertised routes an advertisement's procedure to the connection that sent
// it; a renewal replaces the one before it.
func (s *Station) advertised(c *conn, v cbor.Value) {
	wire, _ := field(v, "advertisement").AsBytes()
	verified, err := record.Verify(wire, s.Profile, time.Now().UnixMilli())
	if err != nil {
		s.t.Errorf("teststation: an advertisement that does not verify: %v", err)
		return
	}
	ad, err := record.ReadProcedureAdvertisement(verified.Record())
	if err != nil || ad.AdvertiserNode != c.nodeID {
		s.t.Errorf("teststation: an advertisement for another node: %v", err)
		return
	}
	s.mu.Lock()
	s.routes[routeKey{ad.RealmID, ad.Procedure}] = c
	s.mu.Unlock()
}

// unadvertised withdraws the route a tombstone names.
func (s *Station) unadvertised(v cbor.Value) {
	wire, _ := field(v, "withdrawal").AsBytes()
	verified, err := record.Verify(wire, s.Profile, time.Now().UnixMilli())
	if err != nil {
		s.t.Errorf("teststation: a withdrawal that does not verify: %v", err)
		return
	}
	tombstone, err := record.ReadTombstone(verified.Record())
	if err != nil || tombstone.WithdrawnType != record.TypeProcedureAdvertisement {
		s.t.Errorf("teststation: a withdrawal of something else: %v", err)
		return
	}
	s.mu.Lock()
	delete(s.routes, routeKey{tombstone.RealmID, tombstone.Procedure})
	s.mu.Unlock()
}

func (s *Station) subscribed(c *conn, v cbor.Value, on bool) {
	realmBytes, _ := field(v, "realm").AsBytes()
	topic, _ := field(v, "topic").AsBytes()
	var realm [32]byte
	copy(realm[:], realmBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	if on {
		c.topics[routeKey{realm, string(topic)}] = true
	} else {
		delete(c.topics, routeKey{realm, string(topic)})
	}
}

// published delivers a verified publication as an EVENT to every connection
// subscribed to its realm and topic.
func (s *Station) published(v cbor.Value) {
	verified, err := frame.VerifyPublication(v, s.Profile, time.Now().UnixMilli())
	if err != nil {
		return
	}
	publication, _ := v.Get("publication")
	event := cbor.Encode(cbor.Map([]cbor.MapEntry{
		{Key: cbor.Text("version"), Val: cbor.Int(frame.ProtocolVersion)},
		{Key: cbor.Text("frame_type"), Val: cbor.Text("event")},
		{Key: cbor.Text("publication"), Val: publication},
		{Key: cbor.Text("delivered_via"), Val: cbor.Text("direct")},
	}))
	key := routeKey{verified.Realm, verified.Topic}
	s.mu.Lock()
	var to []*conn
	for _, c := range s.conns {
		if c.topics[key] {
			to = append(to, c)
		}
	}
	s.mu.Unlock()
	for _, c := range to {
		_ = c.writer.write(event, maxFrameBytes)
	}
}

func field(v cbor.Value, name string) cbor.Value {
	value, _ := v.Get(name)
	return value
}

func keyOf(payload cbor.Value) [32]byte {
	b, _ := field(payload, "key").AsBytes()
	var key [32]byte
	copy(key[:], b)
	return key
}

func list(items [][]byte) cbor.Value {
	out := make([]cbor.Value, len(items))
	for i, b := range items {
		out[i] = cbor.Bytes(b)
	}
	return cbor.List(out)
}

type reader struct{ r io.Reader }

func (f *reader) read(max int) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(f.r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if uint64(length) > uint64(max) {
		return nil, io.ErrUnexpectedEOF
	}
	payload := make([]byte, length)
	_, err := io.ReadFull(f.r, payload)
	return payload, err
}

type writer struct {
	mu sync.Mutex
	w  io.Writer
}

func (f *writer) write(payload []byte, max int) error {
	if len(payload) > max {
		return io.ErrShortWrite
	}
	framed := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(framed, uint32(len(payload)))
	copy(framed[4:], payload)
	f.mu.Lock()
	defer f.mu.Unlock()
	_, err := f.w.Write(framed)
	return err
}

// streamOpenBytes and streamOpenWait bound a dedicated stream's first frame,
// as macula's link bounds it: 1 MiB, within 10 seconds.
const (
	streamOpenBytes = 1024 * 1024
	streamOpenWait  = 10 * time.Second
)

// Relayed is how many dedicated streams the station relays now: each is
// counted until both its directions finished, so a client that does not
// release a stream it is done with keeps it counted.
func (s *Station) Relayed() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.relayed
}

// relayStreams relays each dedicated stream client c opens: a STREAM_OPEN for
// a procedure a connected node advertised goes to that node on a stream the
// station opens, and the two are joined until both directions finish; any
// other opens a relay STREAM_ERROR unknown_next_peer, or is closed.
func (s *Station) relayStreams(ctx context.Context, c *conn) {
	for {
		stream, err := c.qconn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go s.relayStream(ctx, c, stream)
	}
}

func (s *Station) relayStream(ctx context.Context, c *conn, from *quic.Stream) {
	_ = from.SetReadDeadline(time.Now().Add(streamOpenWait))
	open, err := (&reader{r: from}).read(streamOpenBytes)
	_ = from.SetReadDeadline(time.Time{})
	if err != nil {
		release(from)
		return
	}
	v, err := cbor.Decode(open)
	if err != nil {
		release(from)
		return
	}
	request, err := frame.VerifyRequest(v, s.Profile)
	if err != nil || request.FrameType != "stream_open" {
		release(from)
		return
	}
	s.mu.Lock()
	provider := s.routes[routeKey{request.Realm, request.Procedure}]
	s.mu.Unlock()
	if provider == nil || provider.nodeID != request.Target {
		reply, err := frame.SignRelayError(frame.RelayErrorSpec{FrameType: "stream_error", Request: request, Code: "unknown_next_peer"}, s.Key)
		if err == nil {
			_ = (&writer{w: from}).write(cbor.Encode(reply), maxFrameBytes)
		}
		_ = from.Close()
		s.count(from, nil)
		return
	}
	to, err := provider.qconn.OpenStreamSync(ctx)
	if err != nil {
		release(from)
		return
	}
	if err := (&writer{w: to}).write(open, streamOpenBytes); err != nil {
		release(from)
		release(to)
		return
	}
	s.count(from, to)
}

// count joins from and to, when there is a to, and counts the relay until
// both directions have finished; each direction's end closes the other's
// write side, and a reset on either resets the other.
func (s *Station) count(from, to *quic.Stream) {
	s.mu.Lock()
	s.relayed++
	s.mu.Unlock()
	done := make(chan struct{}, 2)
	pipe := func(dst, src *quic.Stream) {
		_, err := io.Copy(dst, src)
		if err != nil {
			release(dst)
			release(src)
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	if to == nil {
		go func() {
			_, _ = io.Copy(io.Discard, from)
			done <- struct{}{}
			done <- struct{}{}
		}()
	} else {
		go pipe(to, from)
		go pipe(from, to)
	}
	go func() {
		<-done
		<-done
		s.mu.Lock()
		s.relayed--
		s.mu.Unlock()
	}()
}

// release abandons a stream in both directions.
func release(stream *quic.Stream) {
	stream.CancelRead(0)
	stream.CancelWrite(0)
}

// RawStream opens a dedicated stream to the client node_id and writes raw on
// it as is. Its Released reports whether the client has released the stream:
// it read EOF or a reset from the client.
func (s *Station) RawStream(ctx context.Context, nodeID [32]byte, raw []byte) (*Raw, error) {
	s.mu.Lock()
	c := s.conns[nodeID]
	s.mu.Unlock()
	if c == nil {
		return nil, io.ErrClosedPipe
	}
	stream, err := c.qconn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if len(raw) > 0 {
		if _, err := stream.Write(raw); err != nil {
			return nil, err
		}
	}
	r := &Raw{stream: stream, released: make(chan struct{})}
	go func() {
		_, _ = io.Copy(io.Discard, stream)
		close(r.released)
	}()
	return r, nil
}

// Raw is a stream a test opened with RawStream.
type Raw struct {
	stream   *quic.Stream
	released chan struct{}
}

// Released is closed once the client has released the stream.
func (r *Raw) Released() <-chan struct{} { return r.released }

// KeepWriting writes to the stream until a write fails, as it does once the
// client stops reading it (STOP_SENDING), and reports whether that happened
// before timeout.
func (r *Raw) KeepWriting(timeout time.Duration) bool {
	chunk := make([]byte, 16*1024)
	deadline := time.Now().Add(timeout)
	_ = r.stream.SetWriteDeadline(deadline)
	for time.Now().Before(deadline) {
		if _, err := r.stream.Write(chunk); err != nil {
			return time.Now().Before(deadline)
		}
	}
	return false
}
