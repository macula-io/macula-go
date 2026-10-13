// Package handshake builds and checks macula's post-quantum connection
// handshake as wire 1.0 freezes it (macula docs/design/WIRE_1_0.md section 4,
// macula#98), the Go counterpart of macula's macula_handshake: the opener,
// challenge, CONNECT, HELLO and status frames of DESIGN_PQ_HANDSHAKE_FRAMES.md
// and DESIGN_NEIGHBOUR_CHANNEL_BINDING.md, as CBOR bytes without the length
// prefix.
//
// The client opens with an opener naming the versions and profiles it speaks.
// The station picks the highest common version and the first profile in the
// client's list it supports, or refuses at once with a HELLO naming its own
// ranges. It answers with a challenge: the chosen version and profile, its own
// ranges, its carried identity key, its TLS binding and status statement, and
// a fresh nonce. The client checks the choice against both ranges (a downgrade
// is detected here), and the challenge against the node_id it dialed and the
// leaf it received, before it signs anything, and answers with CONNECT: its
// ranges again, the chosen profile, its identity and CONNECT keys, the CONNECT
// binding and status statement, and a proof (V3) by the CONNECT key over the
// session, the challenge and the CONNECT itself. The station checks CONNECT,
// the puzzle before any signature, and answers with HELLO, carrying its
// session proof. Status frames renew a peer's statement on the open
// connection.
//
// Version 5 is the only version: every frame, before and after HELLO, carries
// it, and both ends bind to the TLS session through its exporter value E. Each
// end records the highest version it completed with each node_id and never
// completes below it.
//
// Every frame decodes under the decoding rule and must hold exactly the keys of
// its type, each of its type and length. Close reasons are local: a refusing
// station sends only a HELLO with one coarse refusal code.
package handshake

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"slices"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// Version is the handshake and frame version of wire 1.0. A handshake version
// bump is a wire major: there is no version 6 inside wire 1.x.
const Version = 5

// ExporterLabel is the TLS 1.3 exporter label (RFC 8446 section 7.5) the
// handshake binds to, over the context client node_id || station node_id, 32
// bytes.
const ExporterLabel = "EXPORTER-macula-session-v1"

const (
	nonceSize         = 32
	exporterSize      = 32
	maxProtocolInt    = 1 << 53
	mldsaKeySize      = 2592
	maxProfiles       = 8
	connectProofLabel = "MACULA-PQ-CONNECT-PROOF-V3"
	sessionProofLabel = "MACULA-PQ-SESSION-PROOF-V2"
)

// The capability bits CONNECT and HELLO carry (WIRE_1_0.md section 4.7): an
// unsigned integer below 2^53, bits 0 to MaxCapabilityBit reserved. Bits never
// retire and are never reassigned; an unknown bit is ignored. Each one states
// its behaviour towards a peer that lacks it and towards one that claims it
// falsely: waste, never loss, both ways.
const (
	// CapStation is a station.
	CapStation uint64 = 1 << 0
	// CapSwimIndirect is a station that answers SWIM indirect probes.
	CapSwimIndirect uint64 = 1 << 1
	// CapRelayOverloaded is a peer that reads the relay code overloaded
	// (macula#54), which a station sends only to a peer that declares it.
	CapRelayOverloaded uint64 = 1 << 2
	// MaxCapabilityBit is the highest bit of the reserved range.
	MaxCapabilityBit = 52
)

// Exporter is a TLS 1.3 session's exporter: label, context and length to bytes.
// Both ends of one session export the same bytes.
type Exporter func(label string, context []byte, length int) ([]byte, error)

// The close reasons of the handshake, named as macula names them. A binding or
// status statement that fails its check closes with identity's error for it.
var (
	// ErrUnexpectedFrame is a frame of another type than the one expected
	// next.
	ErrUnexpectedFrame = errors.New("handshake: unexpected frame")
	// ErrUnsupportedVersion is a frame of another version than 5, or ranges
	// that share no version (unsupported_version).
	ErrUnsupportedVersion = errors.New("handshake: unsupported_version")
	// ErrProfileUnsupported is profile lists that share no profile, or a
	// CONNECT naming a profile the station did not choose
	// (profile_unsupported).
	ErrProfileUnsupported = errors.New("handshake: profile_unsupported")
	// ErrDowngradeDetected is a challenge whose chosen version or profile is
	// not the highest common one of the client's ranges and the station's
	// repeated ranges (downgrade_detected).
	ErrDowngradeDetected = errors.New("handshake: downgrade_detected")
	// ErrNegotiationMismatch is a CONNECT whose versions or profiles differ
	// from the opener's (negotiation_mismatch).
	ErrNegotiationMismatch = errors.New("handshake: negotiation_mismatch")
	// ErrVersionBelowFloor is a chosen version below the one this end last
	// completed with that node_id (version_below_floor).
	ErrVersionBelowFloor = errors.New("handshake: version_below_floor")
	// ErrMalformedFrame is a frame that does not decode exactly, or a carried
	// key or proof of the wrong form.
	ErrMalformedFrame = identity.ErrMalformedFrame
	// ErrKeyPurposeReuse is a key that would serve two purposes: a CONNECT key
	// that shares a half with its identity key, or a key found in the leaf.
	ErrKeyPurposeReuse = errors.New("handshake: a key would serve two purposes")
	// ErrPeerIdentityMismatch is a station whose derived node_id is not the one
	// dialed. The error is a *PeerIdentityMismatchError.
	ErrPeerIdentityMismatch = errors.New("handshake: the station is not the node dialed")
	// ErrPuzzleInvalid is a client whose node_id does not meet the puzzle.
	ErrPuzzleInvalid = errors.New("handshake: the node_id does not meet the puzzle")
	// ErrProofInvalid is a CONNECT proof that does not verify.
	ErrProofInvalid = errors.New("handshake: the CONNECT proof does not verify")
	// ErrRefused is a HELLO that refuses the connection. The error is a
	// *RefusedError.
	ErrRefused = errors.New("handshake: the station refused the connection")
	// ErrInvalidStationSession is a station session with a puzzle mode or
	// difficulty the design does not have. It refuses every CONNECT.
	ErrInvalidStationSession = errors.New("handshake: the station session has an unknown puzzle mode or difficulty")
	// ErrSessionProofInvalid is a HELLO whose session proof does not verify
	// under the station's identity key over this session.
	ErrSessionProofInvalid = errors.New("handshake: the session proof does not verify")
	// ErrSessionProofMissing is a HELLO that accepts without a session proof.
	ErrSessionProofMissing = errors.New("handshake: the HELLO carries no session proof")
	// ErrSessionProofRate is a station past its session proof budget.
	ErrSessionProofRate = errors.New("handshake: the station's session proof budget is spent")
	// ErrExporterUnavailable is a session whose TLS exporter gave no value.
	ErrExporterUnavailable = errors.New("handshake: the TLS exporter is unavailable")
)

// PeerIdentityMismatchError is ErrPeerIdentityMismatch with the node_id dialed
// and the one derived from the station's key.
type PeerIdentityMismatchError struct {
	Expected [32]byte
	Derived  [32]byte
}

func (e *PeerIdentityMismatchError) Error() string {
	return fmt.Sprintf("handshake: dialed node_id %x, but the station's key derives %x", e.Expected, e.Derived)
}

func (e *PeerIdentityMismatchError) Is(target error) bool { return target == ErrPeerIdentityMismatch }

// RefusalCode is the one coarse reason a refusing HELLO carries.
type RefusalCode string

const (
	// RefusalUnsupportedVersion refuses ranges that share no version, and a
	// frame of another version.
	RefusalUnsupportedVersion RefusalCode = "unsupported_version"
	// RefusalProfileUnsupported refuses an opener whose profiles share none
	// with the station's (WIRE_1_0.md section 4.4).
	RefusalProfileUnsupported RefusalCode = "profile_unsupported"
	// RefusalPuzzleInvalid refuses a node_id that misses the puzzle, which the
	// client can check itself.
	RefusalPuzzleInvalid RefusalCode = "puzzle_invalid"
	// RefusalSessionProofRate refuses a CONNECT past the station's session
	// proof budget.
	RefusalSessionProofRate RefusalCode = "session_proof_rate"
	// RefusalNotAccepted refuses a CONNECT that failed any other check. A
	// refusal code this library does not know reads as this one.
	RefusalNotAccepted RefusalCode = "not_accepted"
)

// RefusedError is ErrRefused with the HELLO's refusal code, and, for a
// refusal before the challenge, the station's ranges it names.
type RefusedError struct {
	Code RefusalCode
	// StationRanges is the station's ranges an early refusal names, nil for a
	// refusal of CONNECT.
	StationRanges *Ranges
}

func (e *RefusedError) Error() string {
	return "handshake: the station refused the connection: " + string(e.Code)
}

func (e *RefusedError) Is(target error) bool { return target == ErrRefused }

// Ranges is what one end speaks: the versions [Min, Max] and its profiles in
// its order of preference, 1 to 8 of them.
type Ranges struct {
	MinVersion, MaxVersion int64
	Profiles               []profile.Profile
}

// Supported is this library's ranges for profile p: version 5 alone, the
// policy of N and N-1 holding 5 alone in wire 1.0.
func Supported(p profile.Profile) Ranges {
	return Ranges{MinVersion: Version, MaxVersion: Version, Profiles: []profile.Profile{p}}
}

// Floor is the highest handshake version an end last completed with a
// node_id, 0 for none. It survives restarts where the host can write, and
// lasts the run where it cannot (WIRE_1_0.md section 4.6).
type Floor func(nodeID [32]byte) int64

func (f Floor) of(nodeID [32]byte) int64 {
	if f == nil {
		return 0
	}
	return f(nodeID)
}

// negotiate is the version and profile a station chooses for a client: the
// highest version in both ranges and this library's, and the first profile in
// the client's list the station supports.
func negotiate(client, station Ranges) (int64, profile.Profile, error) {
	version := min(client.MaxVersion, station.MaxVersion, int64(Version))
	if version < max(client.MinVersion, station.MinVersion) {
		return 0, "", ErrUnsupportedVersion
	}
	for _, p := range client.Profiles {
		if slices.Contains(station.Profiles, p) {
			return version, p, nil
		}
	}
	return 0, "", ErrProfileUnsupported
}

// PuzzleMode is how a station treats a client's node_id puzzle.
type PuzzleMode string

const (
	// PuzzleModeOff does not check the puzzle.
	PuzzleModeOff PuzzleMode = "off"
	// PuzzleModeLogOnly accepts an unsolved puzzle and reports it.
	PuzzleModeLogOnly PuzzleMode = "log_only"
	// PuzzleModeEnforce refuses an unsolved puzzle.
	PuzzleModeEnforce PuzzleMode = "enforce"
)

// PuzzleResult is what a station found of a client's puzzle.
type PuzzleResult string

const (
	PuzzleResultSolved     PuzzleResult = "solved"
	PuzzleResultUnsolved   PuzzleResult = "unsolved"
	PuzzleResultNotChecked PuzzleResult = "not_checked"
)

var (
	openerKeys    = []string{"frame_type", "profiles", "version", "versions"}
	challengeKeys = []string{"frame_type", "identity_key", "nonce", "profile", "profiles", "tls_binding", "tls_status", "version", "versions"}
	// connectKeys hold member_endorsement ALWAYS, empty when the node has none:
	// one layout, so a peer cannot tell from the wire whether a node holds an
	// endorsement or whether a station asks for one.
	connectKeys = []string{"capabilities", "connect_binding", "connect_key", "connect_status", "frame_type", "identity_key",
		"member_endorsement", "profile", "profiles", "proof", "version", "versions"}
	helloProvedKeys   = []string{"accepted", "capabilities", "frame_type", "session_proof", "version"}
	helloAcceptedKeys = []string{"accepted", "capabilities", "frame_type", "version"}
	helloRefusedKeys  = []string{"accepted", "capabilities", "frame_type", "refusal_code", "version"}
	helloEarlyKeys    = []string{"accepted", "frame_type", "profiles", "refusal_code", "version", "versions"}
	// statusLayouts are a STATUS's keys: an envelope frame after HELLO
	// (WIRE_1_0.md section 3.1), it may carry frame_id and sent_at_ms, and
	// ext, which the envelope reads before it; never realm, call_id or
	// source_route.
	statusLayouts = [][]string{
		{"frame_type", "statement", "version"},
		{"frame_id", "frame_type", "statement", "version"},
		{"frame_type", "sent_at_ms", "statement", "version"},
		{"frame_id", "frame_type", "sent_at_ms", "statement", "version"},
	}
)

// Opener is the client's first frame on the control stream: its ranges, and
// nothing that relates to identity.
func Opener(r Ranges) []byte {
	return encodeFrame("opener", rangesEntries(r)...)
}

// Negotiated is what a station chose for a client from its opener: the version
// and profile, and the client's ranges, which its CONNECT must repeat.
type Negotiated struct {
	Version int64
	Profile profile.Profile
	Client  Ranges
}

// ReadOpener is the station's reading of the first frame against its own
// ranges. A frame that is not an opener of exactly its keys is
// ErrMalformedFrame, with no HELLO. Ranges that share no version, or an opener
// of another version, are ErrUnsupportedVersion, and lists that share no
// profile ErrProfileUnsupported; each comes with the refusing HELLO naming the
// station's ranges, to send before closing.
func ReadOpener(opener []byte, station Ranges) (Negotiated, []byte, error) {
	f, err := decode(opener, "opener", openerKeys)
	if errors.Is(err, ErrUnsupportedVersion) {
		return Negotiated{}, helloEarlyRefusal(RefusalUnsupportedVersion, station), err
	}
	if err != nil {
		return Negotiated{}, nil, err
	}
	client := f.ranges()
	version, chosen, err := negotiate(client, station)
	if err != nil {
		return Negotiated{}, helloEarlyRefusal(wireRefusal(err), station), err
	}
	return Negotiated{Version: version, Profile: chosen, Client: client}, nil, nil
}

// StationMaterial is what a station precomputes for its challenges: its
// carried identity key in the profile it chose, and the TLS binding and status
// statement for the leaf the connection presents.
type StationMaterial struct {
	Profile     profile.Profile
	IdentityKey []byte
	TLSBinding  identity.SignedTBS
	TLSStatus   identity.SignedTBS
}

// Challenge is a station's challenge, with a fresh nonce: the version and
// profile it chose, and its own ranges. The station keeps the bytes it sends,
// for the proof check.
func Challenge(m StationMaterial, n Negotiated, station Ranges) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("handshake: challenge nonce: %w", err)
	}
	entries := append(rangesEntries(station),
		entry("nonce", cbor.Bytes(nonce)),
		entry("profile", cbor.Text(string(n.Profile))),
		entry("identity_key", cbor.Bytes(m.IdentityKey)),
		entry("tls_binding", m.TLSBinding.Value()),
		entry("tls_status", m.TLSStatus.Value()))
	return encodeFrameVersion(n.Version, "challenge", entries...), nil
}

// ClientSession is what a client brings to a handshake: its profile, the
// node_id it dialed, the leaf DER it received in this TLS handshake, its
// carried identity key, its CONNECT key with binding and status statement, its
// capability bits, and the time in milliseconds.
type ClientSession struct {
	Profile        profile.Profile
	ExpectedNodeID [32]byte
	Leaf           []byte
	IdentityKey    []byte
	ConnectKey     *identity.NodeKey
	ConnectBinding identity.SignedTBS
	ConnectStatus  identity.SignedTBS
	Capabilities   uint64
	NowMs          int64
	// MemberEndorsement is the realm membership endorsement CONNECT carries:
	// a signed record, or nil for a node that holds none, which sends it empty.
	// It is outside the proof's own fields but inside the CONNECT tbs the proof
	// covers; a station binds it to the node_id the proof establishes.
	MemberEndorsement []byte
	// Ranges is the client's ranges, which its opener carried: Supported(Profile)
	// when zero.
	Ranges Ranges
	// Floor is the highest version this client last completed with each
	// station.
	Floor Floor
	// Export is this connection's TLS exporter.
	Export Exporter
	// connectPublic is the CONNECT key as carried, when ConnectKey is not
	// held: a transcript replayed without private keys.
	connectPublic []byte
}

func (s ClientSession) connectPublicKey() []byte {
	if s.connectPublic != nil {
		return s.connectPublic
	}
	return s.ConnectKey.PublicKey()
}

func (s ClientSession) ranges() Ranges {
	if len(s.Ranges.Profiles) == 0 {
		return Supported(s.Profile)
	}
	return s.Ranges
}

// Station is what a client knows of the station once it has checked the
// challenge, and what its HELLO must answer.
type Station struct {
	NodeID          [32]byte
	IdentityKey     []byte
	TLSBinding      identity.SignedTBS
	StatusExpiresAt int64
	BindingNotAfter int64
	// Version is the version the station chose.
	Version int64
	// What the client proof and the session proof cover.
	profile       profile.Profile
	nonce         []byte
	leaf          []byte
	exporterValue []byte
	challenge     []byte
	connect       []byte
	clientNodeID  [32]byte
}

// ReadChallenge checks a challenge, in macula's order, and signs nothing: the
// frame; the chosen version and profile against the client's ranges and the
// station's repeated ranges (ErrDowngradeDetected), and against the floor for
// the node_id dialed (ErrVersionBelowFloor); the station's carried key in the
// chosen profile; that each key in view serves one purpose; the station's
// node_id against the one dialed; the TLS binding against the leaf received;
// the status statement; and the session's exporter value.
func ReadChallenge(challenge []byte, s ClientSession) (Station, error) {
	f, err := decode(challenge, "challenge", challengeKeys)
	if err != nil {
		return Station{}, err
	}
	version, chosen, err := negotiate(s.ranges(), f.ranges())
	switch {
	case err != nil, version != f.int("version"), chosen != profile.Profile(f.text("profile")), chosen != s.Profile:
		return Station{}, ErrDowngradeDetected
	case version < s.Floor.of(s.ExpectedNodeID):
		return Station{}, ErrVersionBelowFloor
	}
	stationKey := f.bytes("identity_key")
	connectKey := s.connectPublicKey()
	switch {
	case !identity.CarriedKeyWellFormed(stationKey, s.Profile):
		return Station{}, ErrMalformedFrame
	case sharesAHalf(s.IdentityKey, connectKey) || inLeaf(stationKey, s.Leaf) || inLeaf(connectKey, s.Leaf):
		return Station{}, ErrKeyPurposeReuse
	}
	stationNodeID := identity.NodeIDOf(stationKey, s.Profile)
	if stationNodeID != s.ExpectedNodeID {
		return Station{}, &PeerIdentityMismatchError{Expected: s.ExpectedNodeID, Derived: stationNodeID}
	}
	tlsBinding := f.signed("tls_binding")
	binding, err := identity.VerifyTLSBinding(tlsBinding, stationKey, s.Profile, s.Leaf, s.NowMs)
	if err != nil {
		return Station{}, err
	}
	expiresAt, err := identity.VerifyStatus(f.signed("tls_status"), tlsBinding, stationKey, s.Profile, s.NowMs)
	if err != nil {
		return Station{}, err
	}
	clientNodeID := identity.NodeIDOf(s.IdentityKey, s.Profile)
	e, err := sessionExported(s.Export, clientNodeID, stationNodeID)
	if err != nil {
		return Station{}, err
	}
	return Station{
		NodeID:          stationNodeID,
		IdentityKey:     stationKey,
		TLSBinding:      tlsBinding,
		StatusExpiresAt: expiresAt,
		BindingNotAfter: binding.NotAfter,
		Version:         version,
		profile:         s.Profile,
		nonce:           f.bytes("nonce"),
		leaf:            s.Leaf,
		exporterValue:   e,
		challenge:       challenge,
		clientNodeID:    clientNodeID,
	}, nil
}

// AnswerChallenge checks a challenge (ReadChallenge) and, when every check
// passes, returns the CONNECT to send, with its proof V3 by the CONNECT key. A
// refused challenge produces no CONNECT, and nothing is signed before every
// check has passed.
func AnswerChallenge(challenge []byte, s ClientSession) ([]byte, Station, error) {
	station, err := ReadChallenge(challenge, s)
	if err != nil {
		return nil, Station{}, err
	}
	entries := append(rangesEntries(s.ranges()),
		entry("profile", cbor.Text(string(s.Profile))),
		entry("identity_key", cbor.Bytes(s.IdentityKey)),
		entry("connect_key", cbor.Bytes(s.ConnectKey.PublicKey())),
		entry("connect_binding", s.ConnectBinding.Value()),
		entry("connect_status", s.ConnectStatus.Value()),
		entry("capabilities", cbor.Uint64(s.Capabilities)),
		entry("member_endorsement", cbor.Bytes(endorsementBytes(s.MemberEndorsement))))
	tbs := encodeFrameVersion(station.Version, "connect", append(entries, entry("proof", cbor.Bytes(nil)))...)
	proof, err := s.ConnectKey.Sign(station.proofMessage(tbs))
	if err != nil {
		return nil, Station{}, fmt.Errorf("handshake: sign the CONNECT proof: %w", err)
	}
	station.connect = encodeFrameVersion(station.Version, "connect", append(entries, entry("proof", cbor.Bytes(proof)))...)
	return station.connect, station, nil
}

// proofMessage is the client proof V3 over this session and the CONNECT tbs.
func (s Station) proofMessage(connectTBS []byte) []byte {
	return proofMessage(s.nonce, s.NodeID, s.clientNodeID, s.leaf, s.challenge, s.exporterValue, connectTBS)
}

// sessionExported is E for the session, with the client's node_id first in the
// context (the initiator's).
func sessionExported(export Exporter, clientNodeID, stationNodeID [32]byte) ([]byte, error) {
	if export == nil {
		return nil, ErrExporterUnavailable
	}
	e, err := export(ExporterLabel, append(clientNodeID[:], stationNodeID[:]...), exporterSize)
	if err != nil || len(e) != exporterSize {
		return nil, ErrExporterUnavailable
	}
	return e, nil
}

// StationSession is what a station brings to a CONNECT check: its profile, the
// negotiation its challenge carried and the challenge bytes it sent, the leaf
// DER this connection presented, its puzzle difficulty and mode, its
// capability bits, the time in milliseconds, its floor per client, its TLS
// exporter, and a signer for the session proof.
type StationSession struct {
	Profile          profile.Profile
	Negotiated       Negotiated
	Challenge        []byte
	Leaf             []byte
	PuzzleDifficulty int
	PuzzleMode       PuzzleMode
	Capabilities     uint64
	NowMs            int64
	Floor            Floor
	// Export is this connection's TLS exporter, and SignSessionProof signs the
	// session proof with the station's identity key for the client named,
	// within the station's budget (ErrSessionProofRate past it).
	Export           Exporter
	SignSessionProof func(clientNodeID [32]byte, message []byte) ([]byte, error)
}

// Client is what a station knows of an accepted client.
type Client struct {
	NodeID          [32]byte
	IdentityKey     []byte
	ConnectKey      []byte
	ConnectBinding  identity.SignedTBS
	Capabilities    uint64
	StatusExpiresAt int64
	BindingNotAfter int64
	Puzzle          PuzzleResult
	// MemberEndorsement is the endorsement the CONNECT carried, empty when the
	// client holds none. Nothing here checks it: that is the station's policy.
	MemberEndorsement []byte
	// Version is the version the connection completed in.
	Version int64
}

// AcceptConnect checks a CONNECT and returns the HELLO bytes to send. It
// checks, in macula's order: the frame; the client's ranges against its
// opener's (ErrNegotiationMismatch) and the profile against the one chosen
// (ErrProfileUnsupported); the carried keys and the proof's length; that each
// key serves one purpose; the puzzle on the derived node_id before any
// signature; the floor for that node_id (ErrVersionBelowFloor); the CONNECT
// binding and status statement; and the proof V3 against the challenge this
// station sent, the leaf it presented, the session and the CONNECT tbs. It
// signs the session proof only once every check has passed. On a refusal the
// error is the local close reason, and the HELLO refuses with one coarse code.
func AcceptConnect(connect []byte, s StationSession) (Client, []byte, error) {
	client, sessionProof, err := checkConnect(connect, s)
	if err != nil {
		return Client{}, helloRefused(wireRefusal(err)), err
	}
	return client, helloAccepted(s.Capabilities, sessionProof), nil
}

// checkConnect returns the client and the session proof.
func checkConnect(connect []byte, s StationSession) (Client, []byte, error) {
	if !knownPuzzleMode(s.PuzzleMode) || s.PuzzleDifficulty < 0 || s.PuzzleDifficulty > 256 {
		return Client{}, nil, ErrInvalidStationSession
	}
	f, err := decode(connect, "connect", connectKeys)
	if err != nil {
		return Client{}, nil, err
	}
	switch {
	case !sameRanges(f.ranges(), s.Negotiated.Client):
		return Client{}, nil, ErrNegotiationMismatch
	case profile.Profile(f.text("profile")) != s.Negotiated.Profile || s.Negotiated.Profile != s.Profile:
		return Client{}, nil, ErrProfileUnsupported
	}
	identityKey, connectKey, proof := f.bytes("identity_key"), f.bytes("connect_key"), f.bytes("proof")
	switch {
	case !identity.CarriedKeyWellFormed(identityKey, s.Profile) || !identity.CarriedKeyWellFormed(connectKey, s.Profile) ||
		len(proof) != identity.SignatureSize(s.Profile):
		return Client{}, nil, ErrMalformedFrame
	case sharesAHalf(identityKey, connectKey) || inLeaf(connectKey, s.Leaf):
		return Client{}, nil, ErrKeyPurposeReuse
	}
	nodeID := identity.NodeIDOf(identityKey, s.Profile)
	puzzle := puzzleResult(nodeID, s)
	if puzzle == PuzzleResultUnsolved && s.PuzzleMode == PuzzleModeEnforce {
		return Client{}, nil, ErrPuzzleInvalid
	}
	if s.Negotiated.Version < s.Floor.of(nodeID) {
		return Client{}, nil, ErrVersionBelowFloor
	}
	connectBinding := f.signed("connect_binding")
	binding, err := identity.VerifyConnectBinding(connectBinding, identityKey, s.Profile, connectKey, s.NowMs)
	if err != nil {
		return Client{}, nil, err
	}
	expiresAt, err := identity.VerifyStatus(f.signed("connect_status"), connectBinding, identityKey, s.Profile, s.NowMs)
	if err != nil {
		return Client{}, nil, err
	}
	challenge, err := decode(s.Challenge, "challenge", challengeKeys)
	if err != nil {
		return Client{}, nil, ErrProofInvalid
	}
	stationNodeID := identity.NodeIDOf(challenge.bytes("identity_key"), s.Profile)
	e, err := sessionExported(s.Export, nodeID, stationNodeID)
	if err != nil {
		return Client{}, nil, err
	}
	tbs, err := connectTBS(connect)
	if err != nil {
		return Client{}, nil, err
	}
	message := proofMessage(challenge.bytes("nonce"), stationNodeID, nodeID, s.Leaf, s.Challenge, e, tbs)
	if !identity.Verify(message, proof, connectKey, s.Profile) {
		return Client{}, nil, ErrProofInvalid
	}
	if s.SignSessionProof == nil {
		return Client{}, nil, ErrExporterUnavailable
	}
	sessionProof, err := s.SignSessionProof(nodeID,
		sessionProofMessage(e, s.Challenge, connect, stationNodeID, nodeID, helloAccepted(s.Capabilities, nil)))
	if errors.Is(err, ErrSessionProofRate) {
		return Client{}, nil, ErrSessionProofRate
	}
	if err != nil {
		return Client{}, nil, fmt.Errorf("handshake: sign the session proof: %w", err)
	}
	return Client{
		NodeID:            nodeID,
		IdentityKey:       identityKey,
		ConnectKey:        connectKey,
		ConnectBinding:    connectBinding,
		Capabilities:      f.uint("capabilities"),
		StatusExpiresAt:   expiresAt,
		BindingNotAfter:   binding.NotAfter,
		Puzzle:            puzzle,
		MemberEndorsement: endorsementBytes(f.bytes("member_endorsement")),
		Version:           s.Negotiated.Version,
	}, sessionProof, nil
}

// connectTBS is the CONNECT tbs a received CONNECT's proof covers: the frame
// with proof as the zero-length byte string, re-encoded deterministically
// (WIRE_1_0.md section 4.2).
func connectTBS(connect []byte) ([]byte, error) {
	return frameTBS(connect, "proof")
}

// helloTBS is the HELLO tbs a received HELLO's session proof covers: the frame
// with session_proof as the zero-length byte string, re-encoded
// deterministically (WIRE_1_0.md section 4.3).
func helloTBS(hello []byte) ([]byte, error) {
	return frameTBS(hello, "session_proof")
}

// frameTBS is a received frame with its signature field as the zero-length
// byte string, re-encoded deterministically. A frame whose received bytes are
// not its own deterministic encoding is ErrMalformedFrame, so the rebuild is
// exact.
func frameTBS(raw []byte, signatureKey string) ([]byte, error) {
	v, err := cbor.Decode(raw)
	if err != nil || !bytes.Equal(cbor.Encode(v), raw) {
		return nil, ErrMalformedFrame
	}
	entries, _ := v.AsMap()
	rebuilt := make([]cbor.MapEntry, len(entries))
	for i, e := range entries {
		rebuilt[i] = e
		if key, _ := e.Key.AsText(); key == signatureKey {
			rebuilt[i].Val = cbor.Bytes(nil)
		}
	}
	return cbor.Encode(cbor.Map(rebuilt)), nil
}

// endorsementBytes is an endorsement as sent and as handed on: never nil, so
// an absent one is the empty byte string on the wire and to the station.
func endorsementBytes(endorsement []byte) []byte {
	if endorsement == nil {
		return []byte{}
	}
	return endorsement
}

func knownPuzzleMode(mode PuzzleMode) bool {
	return mode == PuzzleModeOff || mode == PuzzleModeLogOnly || mode == PuzzleModeEnforce
}

func puzzleResult(nodeID [32]byte, s StationSession) PuzzleResult {
	switch {
	case s.PuzzleMode == PuzzleModeOff:
		return PuzzleResultNotChecked
	case identity.PuzzleSolved(nodeID, s.PuzzleDifficulty):
		return PuzzleResultSolved
	default:
		return PuzzleResultUnsolved
	}
}

// proofMessage is what the client proof V3 signs (WIRE_1_0.md section 4.2):
// the label, a zero byte, the nonce, the station's and the client's node_ids,
// the SHA-384 of the leaf DER and of the challenge bytes as received, E, and
// the SHA-384 of the CONNECT tbs. Every field has a fixed width, so no two
// field sequences encode to the same bytes.
func proofMessage(nonce []byte, stationNodeID, clientNodeID [32]byte, leafDER, challenge, e, connectTBS []byte) []byte {
	leafHash, challengeHash, connectHash := sha512.Sum384(leafDER), sha512.Sum384(challenge), sha512.Sum384(connectTBS)
	out := make([]byte, 0, len(connectProofLabel)+1+len(nonce)+2*32+3*48+exporterSize)
	out = append(out, connectProofLabel...)
	out = append(out, 0)
	out = append(out, nonce...)
	out = append(out, stationNodeID[:]...)
	out = append(out, clientNodeID[:]...)
	out = append(out, leafHash[:]...)
	out = append(out, challengeHash[:]...)
	out = append(out, e...)
	return append(out, connectHash[:]...)
}

// sessionProofMessage is what the station's session proof signs (WIRE_1_0.md
// section 4.3): the label, a zero byte, E, the SHA-384 of the challenge and of
// CONNECT, the station's and the client's node_ids, and the SHA-384 of the
// HELLO tbs, which covers the station's capabilities at any width and
// accepted. The SHA-384 of the challenge covers the chosen version and profile
// and the station's ranges, and that of CONNECT the client's.
func sessionProofMessage(e, challenge, connect []byte, stationNodeID, clientNodeID [32]byte, helloTBS []byte) []byte {
	challengeHash, connectHash, helloHash := sha512.Sum384(challenge), sha512.Sum384(connect), sha512.Sum384(helloTBS)
	out := make([]byte, 0, len(sessionProofLabel)+1+exporterSize+3*48+2*32)
	out = append(out, sessionProofLabel...)
	out = append(out, 0)
	out = append(out, e...)
	out = append(out, challengeHash[:]...)
	out = append(out, connectHash[:]...)
	out = append(out, stationNodeID[:]...)
	out = append(out, clientNodeID[:]...)
	return append(out, helloHash[:]...)
}

// wireRefusal is the coarse code a refusing HELLO carries for a close reason.
func wireRefusal(err error) RefusalCode {
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		return RefusalUnsupportedVersion
	case errors.Is(err, ErrPuzzleInvalid):
		return RefusalPuzzleInvalid
	case errors.Is(err, ErrSessionProofRate):
		return RefusalSessionProofRate
	default:
		return RefusalNotAccepted
	}
}

func helloAccepted(capabilities uint64, sessionProof []byte) []byte {
	return encodeFrame("hello", entry("accepted", cbor.Int(1)), entry("capabilities", cbor.Uint64(capabilities)),
		entry("session_proof", cbor.Bytes(sessionProof)))
}

func helloRefused(code RefusalCode) []byte {
	return encodeFrame("hello",
		entry("accepted", cbor.Int(0)),
		entry("refusal_code", cbor.Text(string(code))),
		entry("capabilities", cbor.Uint64(0)))
}

// helloEarlyRefusal is the HELLO a station answers an opener with when the
// ranges share no version or the lists no profile, naming its own ranges.
func helloEarlyRefusal(code RefusalCode, station Ranges) []byte {
	if code == RefusalNotAccepted {
		code = RefusalProfileUnsupported
	}
	return encodeFrame("hello", append(rangesEntries(station),
		entry("accepted", cbor.Int(0)),
		entry("refusal_code", cbor.Text(string(code))))...)
}

// ReadHello is the client's reading of HELLO (station, as AnswerChallenge
// returned it): the station's capability bits, or why not. An accepting HELLO
// must carry a session proof that verifies under the station's identity key
// over this session. A refusal is a *RefusedError, which names the station's
// ranges when it came before the challenge.
func ReadHello(hello []byte, station Station) (uint64, error) {
	f, err := decode(hello, "hello", helloProvedKeys, helloAcceptedKeys, helloRefusedKeys, helloEarlyKeys)
	if err != nil {
		return 0, err
	}
	accepted, _ := f["accepted"].AsInt64()
	_, hasCode := f["refusal_code"]
	_, early := f["versions"]
	proof, hasProof := f["session_proof"].AsBytes()
	switch {
	case accepted == 0 && hasCode && early:
		ranges := f.ranges()
		return 0, &RefusedError{Code: refusalCode(f.text("refusal_code")), StationRanges: &ranges}
	case accepted == 0 && hasCode:
		return 0, &RefusedError{Code: refusalCode(f.text("refusal_code"))}
	case accepted != 1 || hasCode || early:
		return 0, ErrMalformedFrame
	case !hasProof:
		return 0, ErrSessionProofMissing
	case len(proof) != identity.SignatureSize(station.profile):
		return 0, ErrMalformedFrame
	}
	tbs, err := helloTBS(hello)
	if err != nil {
		return 0, err
	}
	message := sessionProofMessage(station.exporterValue, station.challenge, station.connect, station.NodeID, station.clientNodeID, tbs)
	if !identity.Verify(message, proof, station.IdentityKey, station.profile) {
		return 0, ErrSessionProofInvalid
	}
	return f.uint("capabilities"), nil
}

// StatusFrame is a status frame carrying a fresh status statement, sent at
// every reissue.
func StatusFrame(statement identity.SignedTBS) []byte {
	return encodeFrame("status", entry("statement", statement.Value()))
}

// Peer is what a connection checks a peer's status frames against: the
// profile, the identity key and binding the handshake verified, and the time
// in milliseconds.
type Peer struct {
	Profile     profile.Profile
	IdentityKey []byte
	Binding     identity.SignedTBS
	NowMs       int64
}

// ReadStatus checks a peer's status frame and returns when its statement
// expires.
func ReadStatus(status []byte, p Peer) (int64, error) {
	f, err := decode(status, "status", statusLayouts...)
	if err != nil {
		return 0, err
	}
	return identity.VerifyStatus(f.signed("statement"), p.Binding, p.IdentityKey, p.Profile, p.NowMs)
}

// frameFields is a decoded handshake frame's values by their keys.
type frameFields map[string]cbor.Value

// decode reads a handshake frame strictly, in macula's order: the decoding
// rule, the version (another is ErrUnsupportedVersion), the frame type, exactly
// the keys of one of the layouts, then the type and length of every field.
func decode(raw []byte, frameType string, layouts ...[]string) (frameFields, error) {
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, ErrMalformedFrame
	}
	entries, isMap := v.AsMap()
	if !isMap {
		return nil, ErrMalformedFrame
	}
	f := make(frameFields, len(entries))
	nonText := 0
	for _, e := range entries {
		key, isText := e.Key.AsText()
		if !isText {
			nonText++
			continue
		}
		f[key] = e.Val
	}
	version, isInt := f["version"].AsInt64()
	switch {
	case !isInt:
		return nil, ErrMalformedFrame
	case version != Version:
		return nil, ErrUnsupportedVersion
	}
	frameTypeValue, isText := f["frame_type"].AsText()
	switch {
	case !isText:
		return nil, ErrMalformedFrame
	case frameTypeValue != frameType:
		return nil, ErrUnexpectedFrame
	}
	if nonText > 0 || !f.hasLayout(layouts) || !f.typed() {
		return nil, ErrMalformedFrame
	}
	return f, nil
}

func (f frameFields) hasLayout(layouts [][]string) bool {
	keys := make([]string, 0, len(f))
	for key := range f {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return slices.ContainsFunc(layouts, func(layout []string) bool { return slices.Equal(keys, layout) })
}

// typed reports whether every field has its type and length.
func (f frameFields) typed() bool {
	for key, v := range f {
		if !fieldTyped(key, v) {
			return false
		}
	}
	return true
}

func fieldTyped(key string, v cbor.Value) bool {
	switch key {
	case "version", "frame_type":
		return true
	case "profile":
		_, isText := v.AsText()
		return isText
	case "versions":
		_, ok := versionsOf(v)
		return ok
	case "profiles":
		_, ok := profilesOf(v)
		return ok
	case "nonce":
		nonce, isBytes := v.AsBytes()
		return isBytes && len(nonce) == nonceSize
	case "identity_key", "connect_key", "proof", "member_endorsement", "session_proof":
		_, isBytes := v.AsBytes()
		return isBytes
	case "tls_binding", "tls_status", "connect_binding", "connect_status", "statement":
		_, err := identity.ParseSignedTBS(v)
		return err == nil
	case "capabilities", "sent_at_ms":
		n, isInt := v.AsInt64()
		return isInt && n >= 0 && n < maxProtocolInt
	case "frame_id":
		id, isBytes := v.AsBytes()
		return isBytes && len(id) == 16
	case "accepted":
		n, isInt := v.AsInt64()
		return isInt && (n == 0 || n == 1)
	case "refusal_code":
		code, isText := v.AsText()
		return isText && code != "" && len(code) <= maxRefusalCodeBytes
	default:
		return false
	}
}

// versionsOf reads versions: [min, max], unsigned integers with min <= max.
func versionsOf(v cbor.Value) ([2]int64, bool) {
	items, isList := v.AsList()
	if !isList || len(items) != 2 {
		return [2]int64{}, false
	}
	lo, loInt := items[0].AsInt64()
	hi, hiInt := items[1].AsInt64()
	return [2]int64{lo, hi}, loInt && hiInt && lo >= 0 && hi < maxProtocolInt && lo <= hi
}

// profilesOf reads profiles: 1 to 8 distinct profile names, as text.
func profilesOf(v cbor.Value) ([]profile.Profile, bool) {
	items, isList := v.AsList()
	if !isList || len(items) == 0 || len(items) > maxProfiles {
		return nil, false
	}
	out := make([]profile.Profile, 0, len(items))
	for _, item := range items {
		name, isText := item.AsText()
		if !isText || name == "" || slices.Contains(out, profile.Profile(name)) {
			return nil, false
		}
		out = append(out, profile.Profile(name))
	}
	return out, true
}

// ranges is a frame's versions and profiles, already typed.
func (f frameFields) ranges() Ranges {
	versions, _ := versionsOf(f["versions"])
	profiles, _ := profilesOf(f["profiles"])
	return Ranges{MinVersion: versions[0], MaxVersion: versions[1], Profiles: profiles}
}

func sameRanges(a, b Ranges) bool {
	return a.MinVersion == b.MinVersion && a.MaxVersion == b.MaxVersion && slices.Equal(a.Profiles, b.Profiles)
}

func rangesEntries(r Ranges) []cbor.MapEntry {
	profiles := make([]cbor.Value, len(r.Profiles))
	for i, p := range r.Profiles {
		profiles[i] = cbor.Text(string(p))
	}
	return []cbor.MapEntry{
		entry("versions", cbor.List([]cbor.Value{cbor.Int(r.MinVersion), cbor.Int(r.MaxVersion)})),
		entry("profiles", cbor.List(profiles)),
	}
}

// maxRefusalCodeBytes bounds a refusal_code on the wire, known or not.
const maxRefusalCodeBytes = 64

// refusalCodes are the HELLO refusal codes this library knows.
var refusalCodes = []string{string(RefusalUnsupportedVersion), string(RefusalProfileUnsupported), string(RefusalPuzzleInvalid),
	string(RefusalSessionProofRate), string(RefusalNotAccepted)}

// refusalCode reads a HELLO's refusal_code, a per-hop enum: one this library
// does not know reads as not_accepted, counted (WIRE_1_0.md section 3.4).
func refusalCode(code string) RefusalCode {
	return RefusalCode(frame.ReadPerHopEnum("refusal_code", code, string(RefusalNotAccepted), refusalCodes...))
}

func (f frameFields) bytes(key string) []byte {
	b, _ := f[key].AsBytes()
	return b
}

func (f frameFields) text(key string) string {
	s, _ := f[key].AsText()
	return s
}

func (f frameFields) int(key string) int64 {
	n, _ := f[key].AsInt64()
	return n
}

func (f frameFields) uint(key string) uint64 {
	n, _ := f[key].AsInt64()
	return uint64(n)
}

func (f frameFields) signed(key string) identity.SignedTBS {
	s, _ := identity.ParseSignedTBS(f[key])
	return s
}

// inLeaf reports whether leafDER holds key's ML-DSA-87 half.
func inLeaf(key, leafDER []byte) bool {
	return len(key) >= mldsaKeySize && bytes.Contains(leafDER, key[:mldsaKeySize])
}

// sharesAHalf reports whether two carried keys share their ML-DSA-87 half, or
// a classical half.
func sharesAHalf(a, b []byte) bool {
	if len(a) < mldsaKeySize || len(b) < mldsaKeySize {
		return bytes.Equal(a, b)
	}
	classicalA, classicalB := a[mldsaKeySize:], b[mldsaKeySize:]
	return bytes.Equal(a[:mldsaKeySize], b[:mldsaKeySize]) || (len(classicalA) > 0 && bytes.Equal(classicalA, classicalB))
}

func encodeFrame(frameType string, entries ...cbor.MapEntry) []byte {
	return encodeFrameVersion(Version, frameType, entries...)
}

// encodeFrameVersion is a frame of a version, which is always 5 in wire 1.0:
// the challenge carries the version the station chose.
func encodeFrameVersion(version int64, frameType string, entries ...cbor.MapEntry) []byte {
	all := append([]cbor.MapEntry{
		entry("version", cbor.Int(version)),
		entry("frame_type", cbor.Text(frameType)),
	}, entries...)
	return cbor.Encode(cbor.Map(all))
}

func entry(key string, v cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(key), Val: v}
}
