// Package stationlink is a client's link to one macula 12 station, as macula's
// macula_station_link is: a QUIC connection dialed to the station its target
// names, one bidirectional control stream, the v4 connection handshake on it,
// then status statements both ways and every frame of the session.
//
// After HELLO the link sends its own status statement at every reissue of the
// client's statement issuer, and ends when the station's statement is
// statusGrace past its expiry or the station's TLS binding reaches its
// not_after. In pq_hybrid every control frame is neighbour-signed with a
// sequence number per direction, from 0 after HELLO; a frame out of sequence
// ends the link.
package stationlink

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"
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
	"github.com/macula-io/macula-go/transport"
)

// HandshakeTimeout bounds the connection handshake, as macula's 30 seconds.
const HandshakeTimeout = 30 * time.Second

// closeLinger is how long Close waits, after its GOODBYE, for the station to
// close the connection before closing it itself: long enough for the GOODBYE
// to leave, since closing a QUIC connection drops what its streams still hold.
const closeLinger = time.Second

// statusGrace is how long past a statement's expiry the link keeps a station
// whose next statement has not arrived: macula's five minutes.
var statusGrace = 5 * time.Minute

// The ways a link ends that are not the connection itself failing.
var (
	// ErrStatusExpired is a station whose status statement lapsed past the
	// grace with no newer one.
	ErrStatusExpired = errors.New("stationlink: the station's status statement expired")
	// ErrBindingExpired is a station whose TLS binding reached its not_after.
	ErrBindingExpired = errors.New("stationlink: the station's TLS binding expired")
	// ErrClosed is a link its owner closed.
	ErrClosed = errors.New("stationlink: the link was closed")
	// ErrInvalidConfig is a Config Dial cannot use: no identity key, no
	// issuer, or a key of another profile than the target's.
	ErrInvalidConfig = errors.New("stationlink: the link configuration is not usable")
)

// GoodbyeError is a station that ended the link with a GOODBYE.
type GoodbyeError struct {
	Reason string
}

func (e *GoodbyeError) Error() string { return "stationlink: the station said goodbye: " + e.Reason }

// Config is what a link is dialed with: the station to reach, the node's
// identity key, the statement issuer that holds its CONNECT key and statements,
// and the realm membership endorsement to present, or none. The issuer must be
// Run: the link sends each statement it reissues, and the station ends a link
// whose statement lapses.
type Config struct {
	Target      transport.Target
	IdentityKey *identity.NodeKey
	Issuer      *identity.StatementIssuer
	// PublicationSeq numbers this identity\'s publications; nil gives the link
	// its own. Links of one identity key share one.
	PublicationSeq    *PublicationSeq
	MemberEndorsement []byte
	// Admission judges the CALLs this link receives; nil gives the link its
	// own, with DefaultAdmissionLimits. Links of one node share one.
	Admission *Admission
	// Share is this link's place in the admission: the station it dialed,
	// host:port, when empty.
	Share string
	// Dedup delivers each publication once; nil gives the link its own.
	// Links of one node share one.
	Dedup *EventDedup
}

// Link is a handshaked link to one station.
type Link struct {
	conn       *quic.Conn
	stream     *quic.Stream
	writer     *frameWriter
	profile    profile.Profile
	key        *identity.NodeKey
	station    handshake.Station
	stationCap uint64
	connection [48]byte

	sendMu  sync.Mutex // orders a neighbour signature's seq with its write
	sendSeq uint64
	recvSeq uint64

	mu           sync.Mutex
	statusTimer  *time.Timer
	bindingTimer *time.Timer
	unsubscribe  func()
	unrouted     map[string]uint64
	pending      map[[16]byte]*pendingCall
	subs         map[topicKey][]*Subscription
	dedup        *EventDedup
	served       map[servedKey]*Served
	streams      map[*Stream]struct{}
	openWait     time.Duration // streamOpenWait when the link was dialed
	admission    *Admission
	share        string
	self         [32]byte
	seq          *PublicationSeq
	done         chan struct{}
	err          error
	endOnce      sync.Once
}

// Dial dials cfg.Target, runs the v4 handshake as a client, and returns the
// link once the station's HELLO accepts it. The handshake is bounded by
// HandshakeTimeout within ctx.
func Dial(ctx context.Context, cfg Config) (*Link, error) {
	if cfg.IdentityKey == nil || cfg.Issuer == nil || cfg.IdentityKey.Profile() != cfg.Target.Profile {
		return nil, ErrInvalidConfig
	}
	if cfg.Admission != nil {
		if err := cfg.Admission.limits.Validate(); err != nil {
			return nil, errors.Join(ErrInvalidConfig, err)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, HandshakeTimeout)
	defer cancel()
	dialed, err := transport.DialTarget(ctx, cfg.Target)
	if err != nil {
		return nil, err
	}
	link, err := handshaken(ctx, dialed, cfg)
	if err != nil {
		_ = dialed.Conn.CloseWithError(0, "handshake failed")
		return nil, err
	}
	return link, nil
}

// handshaken runs the client's side of the handshake on a new control stream.
func handshaken(ctx context.Context, dialed transport.Dialed, cfg Config) (*Link, error) {
	stream, err := dialed.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("stationlink: open the control stream: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetReadDeadline(deadline)
	}
	reader, writer := frameReader{r: stream}, &frameWriter{w: stream}
	if err := writer.write(handshake.Opener(), HandshakeFrameBytes); err != nil {
		return nil, fmt.Errorf("stationlink: send OPENER: %w", err)
	}
	challenge, err := reader.read(HandshakeFrameBytes)
	if err != nil {
		return nil, fmt.Errorf("stationlink: read CHALLENGE: %w", err)
	}
	material, err := cfg.Issuer.ConnectMaterial()
	if err != nil {
		return nil, err
	}
	connect, station, err := handshake.AnswerChallenge(challenge, handshake.ClientSession{
		Profile: cfg.Target.Profile, ExpectedNodeID: cfg.Target.ExpectedNodeID, Leaf: dialed.Leaf,
		IdentityKey: cfg.IdentityKey.PublicKey(), ConnectKey: material.Key, ConnectBinding: material.Binding,
		ConnectStatus: material.Status, NowMs: time.Now().UnixMilli(), MemberEndorsement: cfg.MemberEndorsement,
	})
	if err != nil {
		return nil, err
	}
	if err := writer.write(connect, HandshakeFrameBytes); err != nil {
		return nil, fmt.Errorf("stationlink: send CONNECT: %w", err)
	}
	hello, err := reader.read(HandshakeFrameBytes)
	if err != nil {
		return nil, fmt.Errorf("stationlink: read HELLO: %w", err)
	}
	capabilities, err := handshake.ReadHello(hello)
	if err != nil {
		return nil, err
	}
	_ = stream.SetReadDeadline(time.Time{})
	self, err := cfg.IdentityKey.NodeID()
	if err != nil {
		return nil, err
	}
	seq := cfg.PublicationSeq
	if seq == nil {
		seq = &PublicationSeq{}
	}
	admission := cfg.Admission
	if admission == nil {
		admission = NewAdmission(DefaultAdmissionLimits())
	}
	share := cfg.Share
	if share == "" {
		share = net.JoinHostPort(cfg.Target.Host, strconv.Itoa(int(cfg.Target.Port)))
	}
	dedup := cfg.Dedup
	if dedup == nil {
		dedup = NewEventDedup()
	}
	statements, unsubscribe, err := cfg.Issuer.Subscribe(sha512.Sum384(material.Binding.TBS))
	if err != nil {
		return nil, err
	}
	link := &Link{
		conn: dialed.Conn, stream: stream, writer: writer, profile: cfg.Target.Profile, key: cfg.IdentityKey,
		station: station, stationCap: capabilities, connection: sha512.Sum384(challenge),
		unsubscribe: unsubscribe, unrouted: map[string]uint64{}, pending: map[[16]byte]*pendingCall{},
		subs: map[topicKey][]*Subscription{}, dedup: dedup, self: self, seq: seq,
		served: map[servedKey]*Served{}, streams: map[*Stream]struct{}{}, openWait: streamOpenWait, admission: admission, share: share,
		done: make(chan struct{}),
	}
	link.statusTimer = time.AfterFunc(untilMs(station.StatusExpiresAt, statusGrace), func() { link.end(ErrStatusExpired) })
	link.bindingTimer = time.AfterFunc(untilMs(station.BindingNotAfter, 0), func() { link.end(ErrBindingExpired) })
	go link.sendStatements(statements)
	go link.read(reader)
	go link.acceptStreams()
	go link.probe()
	go func() {
		<-dialed.Conn.Context().Done()
		link.end(context.Cause(dialed.Conn.Context()))
	}()
	return link, nil
}

// untilMs is the time from now until atMs plus grace, never negative.
func untilMs(atMs int64, grace time.Duration) time.Duration {
	return max(time.Until(time.UnixMilli(atMs).Add(grace)), 0)
}

// StationNodeID is the node_id of the station the link reached.
func (l *Link) StationNodeID() [32]byte { return l.station.NodeID }

// TLSState is the TLS state of the link's QUIC connection: the key exchange
// group and cipher suite it settled on, and the station's leaf.
func (l *Link) TLSState() tls.ConnectionState { return l.conn.ConnectionState().TLS }

// StationCapabilities are the capability bits the station's HELLO announced.
func (l *Link) StationCapabilities() uint64 { return l.stationCap }

// Done is closed once the link has ended; Err says why.
func (l *Link) Done() <-chan struct{} { return l.done }

// Err is why the link ended, or nil while it runs.
func (l *Link) Err() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err
}

// Unrouted counts the frames received that nothing on this link handles yet,
// by frame type.
func (l *Link) Unrouted() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make(map[string]uint64, len(l.unrouted))
	for k, v := range l.unrouted {
		out[k] = v
	}
	return out
}

// Close sends a GOODBYE with reason, closes the control stream's sending
// side, waits up to closeLinger for the station to close the connection, and
// ends the link. Closing an ended link does nothing.
func (l *Link) Close(reason string) error {
	select {
	case <-l.done:
		return nil
	default:
	}
	goodbye, err := frame.GoodbyeFrame(reason, nil)
	if err != nil {
		return err
	}
	sendErr := l.sendControl(goodbye)
	if sendErr == nil {
		_ = l.stream.Close()
		select {
		case <-l.conn.Context().Done():
		case <-time.After(closeLinger):
		}
	}
	l.end(ErrClosed)
	return sendErr
}

// sendControl sends a version-2 frame on the control stream, neighbour-signed
// with the next seq when the profile signs its type.
func (l *Link) sendControl(v cbor.Value) error {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	signed, err := frame.SignNeighbour(v, l.key, frame.NeighbourLink{Connection: l.connection, Seq: l.sendSeq})
	if err != nil {
		return err
	}
	if frame.NeighbourSigned(l.profile, frameTypeOf(v)) {
		l.sendSeq++
	}
	return l.writer.write(cbor.Encode(signed), MaxFrameBytes)
}

// sendStatements sends each statement the issuer reissues as a STATUS, until
// the link ends. A STATUS carries no neighbour signature and takes no seq.
func (l *Link) sendStatements(statements <-chan identity.SignedTBS) {
	for {
		select {
		case <-l.done:
			return
		case statement, ok := <-statements:
			if !ok {
				return
			}
			if err := l.writer.write(handshake.StatusFrame(statement), MaxFrameBytes); err != nil {
				l.end(err)
				return
			}
		}
	}
}

// read reads the station's frames until the link ends.
func (l *Link) read(reader frameReader) {
	for {
		payload, err := reader.read(MaxFrameBytes)
		if err != nil {
			l.end(err)
			return
		}
		if err := l.received(payload); err != nil {
			l.end(err)
			return
		}
	}
}

// received handles one frame from the station: a STATUS renews the station's
// statement, every other frame is opened from its neighbour signature at the
// next seq, and a GOODBYE ends the link.
func (l *Link) received(payload []byte) error {
	v, err := cbor.Decode(payload)
	if err != nil {
		return fmt.Errorf("%w: %w", frame.ErrMalformedFrame, err)
	}
	frameType := frameTypeOf(v)
	if frameType == "status" {
		return l.statusRenewed(payload)
	}
	opened, err := frame.VerifyNeighbour(v, frame.NeighbourPeer{
		Profile: l.profile, PeerKey: l.station.IdentityKey, Connection: l.connection, Seq: l.recvSeq})
	if err != nil {
		return err
	}
	if frame.NeighbourSigned(l.profile, frameType) {
		l.recvSeq++
	}
	switch frameType {
	case "event":
		l.evented(opened)
		return nil
	case "result", "error":
		l.replied(opened)
		return nil
	case "call":
		l.called(opened)
		return nil
	case "goodbye":
		reason, _ := fieldOf(opened, "reason").AsText()
		return &GoodbyeError{Reason: reason}
	default:
		l.mu.Lock()
		l.unrouted[frameType]++
		l.mu.Unlock()
		return nil
	}
}

// statusRenewed checks a station's STATUS and moves its expiry timer.
func (l *Link) statusRenewed(payload []byte) error {
	expiresAt, err := handshake.ReadStatus(payload, handshake.Peer{
		Profile: l.profile, IdentityKey: l.station.IdentityKey, Binding: l.station.TLSBinding, NowMs: time.Now().UnixMilli()})
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.statusTimer != nil {
		l.statusTimer.Reset(untilMs(expiresAt, statusGrace))
	}
	return nil
}

// end ends the link once, with err: it stops the timers and the statement
// subscription and closes the connection.
func (l *Link) end(err error) {
	l.endOnce.Do(func() {
		l.mu.Lock()
		l.err = err
		for _, timer := range []*time.Timer{l.statusTimer, l.bindingTimer} {
			if timer != nil {
				timer.Stop()
			}
		}
		l.mu.Unlock()
		l.unsubscribe()
		l.closeSubscriptions()
		l.endServed(err)
		l.endStreams(err)
		_ = l.conn.CloseWithError(0, "link ended")
		close(l.done)
	})
}

func frameTypeOf(v cbor.Value) string {
	s, _ := fieldOf(v, "frame_type").AsText()
	return s
}

func fieldOf(v cbor.Value, name string) cbor.Value {
	entries, _ := v.AsMap()
	for _, e := range entries {
		if key, _ := e.Key.AsText(); key == name {
			return e.Val
		}
	}
	return cbor.Null()
}
