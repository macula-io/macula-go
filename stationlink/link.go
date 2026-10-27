// Package stationlink is a client's link to one macula station, as macula's
// macula_station_link is: a QUIC connection dialed to the station its target
// names, one bidirectional control stream, the wire 1.0 connection handshake on
// it (version 5, macula docs/design/WIRE_1_0.md section 4), then status
// statements both ways and every frame of the session.
//
// After HELLO the link sends its own status statement at every reissue of the
// client's statement issuer, and ends when the station's statement is
// statusGrace past its expiry or the station's TLS binding reaches its
// not_after. No frame carries a neighbour signature: the session proofs
// authenticated the station once, and QUIC's AEAD authenticates every frame.
package stationlink

import (
	"context"
	"crypto/sha512"
	"crypto/tls"
	"errors"
	"fmt"
	"maps"
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
	"github.com/macula-io/macula-go/seal"
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
	// Keyring holds this identity's KEM keys (macula 13, E2E design,
	// amendment A1): with it the link opens sealed requests; without it it
	// refuses them, holding no key. Links of one identity share one.
	Keyring *seal.Keyring
	// KEMAdvertise names the keyring's current key in the advertisements of
	// procedures served confidentially (ConfidentialPreferred or
	// ConfidentialRequired). Off by default: switch it on only once every
	// station runs macula 12.11 or later, which stores and routes a keyed
	// advertisement, and every caller runs 13 (the station floor).
	KEMAdvertise bool
	// KEMKeyInRefusal carries this node's KEM key in a sealed_required refusal,
	// in the reply's and the stream frame's signed tbs under seal.kem_key, so
	// the caller seals to it at once (DESIGN_E2E_SEALED_BY_DEFAULT.md section
	// 3). Off by default, and it is release A: a caller that has not read the
	// extension yet refuses the refusal as malformed and waits out its
	// deadline, so it goes on only once every caller is on A0.
	KEMKeyInRefusal bool
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
	pongs      chan [16]byte // liveness answers, for probe

	sendMu sync.Mutex // orders the link's own control frames

	mu           sync.Mutex
	statusTimer  *time.Timer
	bindingTimer *time.Timer
	unsubscribe  func()
	unrouted     map[string]uint64
	refusals     map[string]uint64
	awaiting     map[registration]chan frame.RegisterAck
	pending      map[[16]byte]*pendingCall
	subs         map[topicKey][]*Subscription
	subscribing  map[topicKey]*pendingSubscribe
	dedup        *EventDedup
	served       map[servedKey]*Served
	streams      map[*Stream]struct{}
	openWait     time.Duration // streamOpenWait when the link was dialed
	admission    *Admission
	share        string
	keyring      *seal.Keyring
	kemAdvertise bool
	// kemKeyInRefusal carries the key in a sealed_required refusal (release A).
	kemKeyInRefusal bool
	// drains counts the refusal drains this link runs now (stream_serve.go).
	drains  int
	self    [32]byte
	seq     *PublicationSeq
	done    chan struct{}
	err     error
	endOnce sync.Once
}

// Dial dials cfg.Target, runs the wire 1.0 handshake as a client, and returns
// the link once the station's HELLO accepts it. The handshake is version 5
// alone, never completes below the version this process last completed with
// the station (its floor), and is bounded by HandshakeTimeout within ctx.
func Dial(ctx context.Context, cfg Config) (*Link, error) {
	if cfg.IdentityKey == nil || cfg.Issuer == nil || cfg.IdentityKey.Profile() != cfg.Target.Profile ||
		(cfg.Keyring != nil && cfg.Keyring.Profile() != cfg.Target.Profile) || (cfg.KEMAdvertise && cfg.Keyring == nil) {
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
		countRefusal(err)
		_ = dialed.Conn.CloseWithError(0, "handshake failed")
		return nil, err
	}
	return link, nil
}

// countRefusal counts the handshake refusals HandshakeCounters reports.
func countRefusal(err error) {
	for name, known := range map[string]error{
		"downgrade_detected": handshake.ErrDowngradeDetected, "version_below_floor": handshake.ErrVersionBelowFloor,
		"session_proof_invalid": handshake.ErrSessionProofInvalid, "session_proof_missing": handshake.ErrSessionProofMissing,
		"exporter_unavailable": handshake.ErrExporterUnavailable,
	} {
		if errors.Is(err, known) {
			floors.count(name)
		}
	}
}

// exchangeHandshake runs OPENER, CHALLENGE, CONNECT and HELLO on the control
// stream, and returns the station's statement as its HELLO carried it.
func exchangeHandshake(dialed transport.Dialed, cfg Config, reader frameReader, writer *frameWriter) (handshake.Station, identity.ConnectMaterial, uint64, error) {
	if err := writer.write(handshake.Opener(handshake.Supported(cfg.Target.Profile)), HandshakeFrameBytes); err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, fmt.Errorf("stationlink: send OPENER: %w", err)
	}
	challenge, err := reader.read(HandshakeFrameBytes)
	if err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, fmt.Errorf("stationlink: read CHALLENGE: %w", err)
	}
	material, err := cfg.Issuer.ConnectMaterial()
	if err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, err
	}
	connect, station, err := handshake.AnswerChallenge(challenge, handshake.ClientSession{
		Profile: cfg.Target.Profile, ExpectedNodeID: cfg.Target.ExpectedNodeID, Leaf: dialed.Leaf,
		IdentityKey: cfg.IdentityKey.PublicKey(), ConnectKey: material.Key, ConnectBinding: material.Binding,
		ConnectStatus: material.Status, NowMs: time.Now().UnixMilli(), MemberEndorsement: cfg.MemberEndorsement,
		Floor: floors.of, Export: exporterOf(dialed.Conn),
	})
	if err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, err
	}
	if err := writer.write(connect, HandshakeFrameBytes); err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, fmt.Errorf("stationlink: send CONNECT: %w", err)
	}
	hello, err := reader.read(HandshakeFrameBytes)
	if err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, fmt.Errorf("stationlink: read HELLO: %w", err)
	}
	capabilities, err := handshake.ReadHello(hello, station)
	if err != nil {
		return handshake.Station{}, identity.ConnectMaterial{}, 0, err
	}
	return station, material, capabilities, nil
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
	station, material, capabilities, err := exchangeHandshake(dialed, cfg, reader, writer)
	if err != nil {
		return nil, err
	}
	if !floors.completed(station.NodeID, station.Version) {
		return nil, fmt.Errorf("stationlink: version %d: %w", station.Version, handshake.ErrVersionBelowFloor)
	}
	_ = stream.SetReadDeadline(time.Time{})
	self, err := cfg.IdentityKey.NodeID()
	if err != nil {
		return nil, err
	}
	seq, admission, dedup, share := linkDefaults(cfg)
	statements, unsubscribe, err := cfg.Issuer.Subscribe(sha512.Sum384(material.Binding.TBS))
	if err != nil {
		return nil, err
	}
	link := &Link{
		conn: dialed.Conn, stream: stream, writer: writer, profile: cfg.Target.Profile, key: cfg.IdentityKey,
		station: station, stationCap: capabilities,
		pongs:       make(chan [16]byte, 1),
		unsubscribe: unsubscribe, unrouted: map[string]uint64{}, refusals: map[string]uint64{}, awaiting: map[registration]chan frame.RegisterAck{}, subscribing: map[topicKey]*pendingSubscribe{}, pending: map[[16]byte]*pendingCall{},
		subs: map[topicKey][]*Subscription{}, dedup: dedup, self: self, seq: seq,
		served: map[servedKey]*Served{}, streams: map[*Stream]struct{}{}, openWait: streamOpenWait, admission: admission, share: share,
		keyring: cfg.Keyring, kemAdvertise: cfg.KEMAdvertise, kemKeyInRefusal: cfg.KEMKeyInRefusal,
		done: make(chan struct{}),
	}
	// Under the link's lock: end reads the timers under the same lock.
	link.mu.Lock()
	link.statusTimer = time.AfterFunc(untilMs(station.StatusExpiresAt, statusGrace), func() { link.end(ErrStatusExpired) })
	link.bindingTimer = time.AfterFunc(untilMs(station.BindingNotAfter, 0), func() { link.end(ErrBindingExpired) })
	link.mu.Unlock()
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

// exporterOf is conn's TLS 1.3 exporter (RFC 8446 section 7.5).
func exporterOf(conn *quic.Conn) handshake.Exporter {
	state := conn.ConnectionState().TLS
	return state.ExportKeyingMaterial
}

// HandshakeVersion is the handshake version the link completed: 5, wire
// 1.0's only one.
func (l *Link) HandshakeVersion() int64 { return l.station.Version }

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

// sendControl sends a frame on the control stream, as it is: the session
// proofs authenticated the station once, and QUIC's AEAD authenticates every
// frame after HELLO.
func (l *Link) sendControl(v cbor.Value) error {
	l.sendMu.Lock()
	defer l.sendMu.Unlock()
	return l.writer.write(cbor.Encode(v), MaxFrameBytes)
}

// sendStatements sends each statement the issuer reissues as a STATUS, until
// the link ends.
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

// controlFrameTypes are the frame types a link acts on after HELLO; any
// other is unknown to it.
var controlFrameTypes = map[string]bool{
	"status": true, "event": true, "result": true, "error": true, "call": true, "goodbye": true,
	"liveness_ping": true, "liveness_pong": true, "register_ack": true,
}

// readControl reads one control frame under the wire 1.0 rules: its envelope
// (frame.ReadEnvelope), and a liveness frame's own table. It reports whether
// the link acts on its type; one it does not is counted as
// wire_unknown_frame_type, its body unread. A frame refused here is
// frame.ErrExtensionUnsupported or frame.ErrMalformedFrame.
func readControl(payload []byte) (frame.Envelope, bool, error) {
	v, err := cbor.Decode(payload)
	if err != nil {
		return frame.Envelope{}, false, fmt.Errorf("%w: %w", frame.ErrMalformedFrame, err)
	}
	envelope, err := frame.ReadEnvelope(v)
	if err != nil {
		frame.CountExtRefused(err)
		return frame.Envelope{}, false, err
	}
	if !controlFrameTypes[envelope.FrameType] {
		frame.CountUnknownFrameType()
		return envelope, false, nil
	}
	if envelope.FrameType == "liveness_ping" || envelope.FrameType == "liveness_pong" {
		if _, _, isLiveness := frame.LivenessNonce(envelope.Frame); !isLiveness {
			return frame.Envelope{}, false, fmt.Errorf("%w: %s", frame.ErrMalformedFrame, envelope.FrameType)
		}
	}
	return envelope, true, nil
}

// received handles one frame from the station, read by readControl: one that
// does not read ends the link as malformed_frame, one carrying an unknown
// critical extension is dropped and counted as extension_unsupported, and one
// of a type the link does not act on is dropped and counted, each with the
// link left up. Then a STATUS renews the station's statement, a liveness frame
// is answered or handed to the probe, a REGISTER_ACK's refusal is counted, and
// a GOODBYE ends the link.
func (l *Link) received(payload []byte) error {
	envelope, known, err := readControl(payload)
	switch {
	case errors.Is(err, frame.ErrExtensionUnsupported):
		l.count("extension_unsupported")
		return nil
	case err != nil:
		return err
	case !known:
		l.count(envelope.FrameType)
		return nil
	}
	frameType := envelope.FrameType
	if frameType == "status" {
		return l.statusRenewed(cbor.Encode(envelope.Frame))
	}
	opened := envelope.Frame
	if livenessType, nonce, isLiveness := frame.LivenessNonce(opened); isLiveness {
		return l.liveness(livenessType, nonce)
	}
	switch frameType {
	case "event":
		l.evented(opened)
	case "result", "error":
		l.replied(opened)
	case "call":
		l.called(opened)
	case "register_ack":
		return l.registerAcked(opened)
	case "goodbye":
		goodbye, err := frame.ReadControl(opened)
		if err != nil {
			return err
		}
		reason, _ := fieldOf(goodbye, "reason").AsText()
		return &GoodbyeError{Reason: reason}
	}
	return nil
}

// registerAcked reads the station's REGISTER_ACK: it answers the Serve or
// Subscribe waiting on its registration (register.go), a refusal is counted by
// its reason, an ack of a kind this library does not know is ignored, and a
// malformed one ends the link.
func (l *Link) registerAcked(v cbor.Value) error {
	ack, known, err := frame.ReadRegisterAck(v)
	if err != nil || !known {
		return err
	}
	l.acknowledged(ack)
	if ack.Accepted {
		return nil
	}
	l.mu.Lock()
	l.refusals[ack.Reason]++
	l.mu.Unlock()
	return nil
}

// RegisterRefusals counts the station's refusals of this link's ADVERTISE,
// UNADVERTISE, SUBSCRIBE and UNSUBSCRIBE (REGISTER_ACK, WIRE_1_0.md section
// 3.5), by reason: a reason this library does not know counts as refused.
func (l *Link) RegisterRefusals() map[string]uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maps.Clone(l.refusals)
}

// liveness answers the station's liveness_ping with a liveness_pong of the same
// nonce, and hands a liveness_pong to the probe. Neither goes further.
func (l *Link) liveness(frameType string, nonce [16]byte) error {
	if frameType == "liveness_ping" {
		return l.sendControl(frame.LivenessPongFrame(nonce))
	}
	select {
	case l.pongs <- nonce:
	default:
	}
	return nil
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

// linkDefaults is the parts of a link its config may leave out, defaulted.
func linkDefaults(cfg Config) (seq *PublicationSeq, admission *Admission, dedup *EventDedup, share string) {
	seq = cfg.PublicationSeq
	if seq == nil {
		seq = &PublicationSeq{}
	}
	admission = cfg.Admission
	if admission == nil {
		admission = NewAdmission(DefaultAdmissionLimits())
	}
	share = cfg.Share
	if share == "" {
		share = net.JoinHostPort(cfg.Target.Host, strconv.Itoa(int(cfg.Target.Port)))
	}
	dedup = cfg.Dedup
	if dedup == nil {
		dedup = NewEventDedup()
	}
	return seq, admission, dedup, share
}
