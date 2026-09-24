// Package handshake builds and checks macula 11.0.0's post-quantum connection
// handshake, the Go counterpart of macula's macula_handshake: the opener,
// challenge, CONNECT, HELLO and status frames of DESIGN_PQ_HANDSHAKE_FRAMES.md
// (D16 and D22), as CBOR bytes without the length prefix.
//
// The client opens with an opener. The station answers with a challenge: its
// carried identity key, its TLS binding and status statement, and a fresh
// nonce. The client checks the challenge against the node_id it dialed and the
// leaf it received, before it signs anything, and answers with CONNECT: its
// identity and CONNECT keys, the CONNECT binding and status statement, and a
// proof by the CONNECT key. The station checks CONNECT, the puzzle before any
// signature, and answers with HELLO. Status frames renew a peer's statement on
// the open connection.
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
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// Version is the post-quantum handshake's frame version: 4, as macula 12's.
// CONNECT gained member_endorsement, and macula matches key sets exactly, so a
// peer on version 3 hears unsupported_version rather than malformed_frame.
const Version = 4

const (
	nonceSize         = 32
	maxProtocolInt    = 1 << 53
	mldsaKeySize      = 2592
	connectProofLabel = "MACULA-PQ-CONNECT-PROOF-V1"
)

// The close reasons of the handshake, named as macula names them. A binding or
// status statement that fails its check closes with identity's error for it.
var (
	// ErrUnexpectedFrame is a frame of another type than the one expected
	// next.
	ErrUnexpectedFrame = errors.New("handshake: unexpected frame")
	// ErrUnsupportedVersion is a frame of another version than 4.
	ErrUnsupportedVersion = errors.New("handshake: unsupported frame version")
	// ErrMalformedFrame is a frame that does not decode exactly, or a carried
	// key or proof of the wrong form.
	ErrMalformedFrame = identity.ErrMalformedFrame
	// ErrProfileMismatch is a challenge that names another profile.
	ErrProfileMismatch = errors.New("handshake: the peer names another profile")
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
	// RefusalUnsupportedVersion refuses frames that are not version 4.
	RefusalUnsupportedVersion RefusalCode = "unsupported_version"
	// RefusalPuzzleInvalid refuses a node_id that misses the puzzle, which the
	// client can check itself.
	RefusalPuzzleInvalid RefusalCode = "puzzle_invalid"
	// RefusalNotAccepted refuses a CONNECT that failed any other check.
	RefusalNotAccepted RefusalCode = "not_accepted"
)

// RefusedError is ErrRefused with the HELLO's refusal code.
type RefusedError struct {
	Code RefusalCode
}

func (e *RefusedError) Error() string {
	return "handshake: the station refused the connection: " + string(e.Code)
}

func (e *RefusedError) Is(target error) bool { return target == ErrRefused }

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
	openerKeys    = []string{"frame_type", "version"}
	challengeKeys = []string{"frame_type", "identity_key", "nonce", "profile", "tls_binding", "tls_status", "version"}
	// connectKeys hold member_endorsement ALWAYS, empty when the node has none,
	// as macula 12's CONNECT: one layout, so a peer cannot tell from the wire
	// whether a node holds an endorsement or whether a station asks for one.
	connectKeys       = []string{"capabilities", "connect_binding", "connect_key", "connect_status", "frame_type", "identity_key", "member_endorsement", "proof", "version"}
	helloAcceptedKeys = []string{"accepted", "capabilities", "frame_type", "version"}
	helloRefusedKeys  = []string{"accepted", "capabilities", "frame_type", "refusal_code", "version"}
	statusKeys        = []string{"frame_type", "statement", "version"}
)

// Opener is the client's first frame on the control stream. It carries
// nothing that relates to identity.
func Opener() []byte {
	return encodeFrame("opener")
}

// ReadOpener is the station's check of the first frame.
func ReadOpener(frame []byte) error {
	_, err := decode(frame, "opener", openerKeys)
	return err
}

// StationMaterial is what a station precomputes for its challenges: its
// carried identity key, and the TLS binding and status statement for the leaf
// the connection presents.
type StationMaterial struct {
	Profile     profile.Profile
	IdentityKey []byte
	TLSBinding  identity.SignedTBS
	TLSStatus   identity.SignedTBS
}

// Challenge is a station's challenge, with a fresh nonce. The station keeps the
// bytes it sends, for the proof check.
func Challenge(m StationMaterial) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("handshake: challenge nonce: %w", err)
	}
	return encodeFrame("challenge",
		entry("nonce", cbor.Bytes(nonce)),
		entry("profile", cbor.Text(string(m.Profile))),
		entry("identity_key", cbor.Bytes(m.IdentityKey)),
		entry("tls_binding", m.TLSBinding.Value()),
		entry("tls_status", m.TLSStatus.Value())), nil
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
	// It is outside the proof; a station binds it to the node_id the proof
	// establishes.
	MemberEndorsement []byte
}

// Station is what a client knows of the station once it has checked the
// challenge.
type Station struct {
	NodeID          [32]byte
	IdentityKey     []byte
	TLSBinding      identity.SignedTBS
	StatusExpiresAt int64
	BindingNotAfter int64
}

// AnswerChallenge checks a challenge and, when every check passes, returns the
// CONNECT to send. It checks, in macula's order: the frame, the profile, the
// station's carried key, that each key in view serves one purpose, the
// station's node_id against the one dialed, the TLS binding against the leaf
// received, and the status statement. It signs nothing before all of them
// pass, and a refused challenge produces no CONNECT.
func AnswerChallenge(challenge []byte, s ClientSession) ([]byte, Station, error) {
	f, err := decode(challenge, "challenge", challengeKeys)
	if err != nil {
		return nil, Station{}, err
	}
	stationKey := f.bytes("identity_key")
	connectKey := s.ConnectKey.PublicKey()
	switch {
	case f.text("profile") != string(s.Profile):
		return nil, Station{}, ErrProfileMismatch
	case !identity.CarriedKeyWellFormed(stationKey, s.Profile):
		return nil, Station{}, ErrMalformedFrame
	case sharesAHalf(s.IdentityKey, connectKey) || inLeaf(stationKey, s.Leaf) || inLeaf(connectKey, s.Leaf):
		return nil, Station{}, ErrKeyPurposeReuse
	}
	stationNodeID := identity.NodeIDOf(stationKey, s.Profile)
	if stationNodeID != s.ExpectedNodeID {
		return nil, Station{}, &PeerIdentityMismatchError{Expected: s.ExpectedNodeID, Derived: stationNodeID}
	}
	tlsBinding := f.signed("tls_binding")
	binding, err := identity.VerifyTLSBinding(tlsBinding, stationKey, s.Profile, s.Leaf, s.NowMs)
	if err != nil {
		return nil, Station{}, err
	}
	expiresAt, err := identity.VerifyStatus(f.signed("tls_status"), tlsBinding, stationKey, s.Profile, s.NowMs)
	if err != nil {
		return nil, Station{}, err
	}
	clientNodeID := identity.NodeIDOf(s.IdentityKey, s.Profile)
	proof, err := s.ConnectKey.Sign(proofMessage(f.bytes("nonce"), stationNodeID, clientNodeID, s.Leaf, challenge))
	if err != nil {
		return nil, Station{}, fmt.Errorf("handshake: sign the CONNECT proof: %w", err)
	}
	connect := encodeFrame("connect",
		entry("identity_key", cbor.Bytes(s.IdentityKey)),
		entry("connect_key", cbor.Bytes(connectKey)),
		entry("connect_binding", s.ConnectBinding.Value()),
		entry("connect_status", s.ConnectStatus.Value()),
		entry("proof", cbor.Bytes(proof)),
		entry("capabilities", cbor.Uint64(s.Capabilities)),
		entry("member_endorsement", cbor.Bytes(endorsementBytes(s.MemberEndorsement))))
	station := Station{
		NodeID:          stationNodeID,
		IdentityKey:     stationKey,
		TLSBinding:      tlsBinding,
		StatusExpiresAt: expiresAt,
		BindingNotAfter: binding.NotAfter,
	}
	return connect, station, nil
}

// StationSession is what a station brings to a CONNECT check: its profile, the
// challenge bytes it sent, the leaf DER this connection presented, its puzzle
// difficulty and mode, its capability bits, and the time in milliseconds.
type StationSession struct {
	Profile          profile.Profile
	Challenge        []byte
	Leaf             []byte
	PuzzleDifficulty int
	PuzzleMode       PuzzleMode
	Capabilities     uint64
	NowMs            int64
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
}

// AcceptConnect checks a CONNECT and returns the HELLO bytes to send. It
// checks, in macula's order: the frame, the carried keys and the proof's
// length, that each key serves one purpose, the puzzle on the derived node_id
// before any signature, the CONNECT binding and status statement, and the proof
// against the challenge this station sent and the leaf it presented. On a
// refusal the error is the local close reason, and the HELLO refuses with one
// coarse code.
func AcceptConnect(connect []byte, s StationSession) (Client, []byte, error) {
	client, err := checkConnect(connect, s)
	if err != nil {
		return Client{}, helloRefused(wireRefusal(err), s.Capabilities), err
	}
	return client, helloAccepted(s.Capabilities), nil
}

func checkConnect(connect []byte, s StationSession) (Client, error) {
	if !knownPuzzleMode(s.PuzzleMode) || s.PuzzleDifficulty < 0 || s.PuzzleDifficulty > 256 {
		return Client{}, ErrInvalidStationSession
	}
	f, err := decode(connect, "connect", connectKeys)
	if err != nil {
		return Client{}, err
	}
	identityKey, connectKey, proof := f.bytes("identity_key"), f.bytes("connect_key"), f.bytes("proof")
	switch {
	case !identity.CarriedKeyWellFormed(identityKey, s.Profile) || !identity.CarriedKeyWellFormed(connectKey, s.Profile) ||
		len(proof) != identity.SignatureSize(s.Profile):
		return Client{}, ErrMalformedFrame
	case sharesAHalf(identityKey, connectKey) || inLeaf(connectKey, s.Leaf):
		return Client{}, ErrKeyPurposeReuse
	}
	nodeID := identity.NodeIDOf(identityKey, s.Profile)
	puzzle := puzzleResult(nodeID, s)
	if puzzle == PuzzleResultUnsolved && s.PuzzleMode == PuzzleModeEnforce {
		return Client{}, ErrPuzzleInvalid
	}
	connectBinding := f.signed("connect_binding")
	binding, err := identity.VerifyConnectBinding(connectBinding, identityKey, s.Profile, connectKey, s.NowMs)
	if err != nil {
		return Client{}, err
	}
	expiresAt, err := identity.VerifyStatus(f.signed("connect_status"), connectBinding, identityKey, s.Profile, s.NowMs)
	if err != nil {
		return Client{}, err
	}
	if !proofVerifies(s, nodeID, connectKey, proof) {
		return Client{}, ErrProofInvalid
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
	}, nil
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

// proofVerifies checks a CONNECT proof against the challenge the station sent
// and the leaf it presented. The station's own challenge decodes: it built it.
func proofVerifies(s StationSession, clientNodeID [32]byte, connectKey, proof []byte) bool {
	challenge, err := decode(s.Challenge, "challenge", challengeKeys)
	if err != nil {
		return false
	}
	stationNodeID := identity.NodeIDOf(challenge.bytes("identity_key"), s.Profile)
	message := proofMessage(challenge.bytes("nonce"), stationNodeID, clientNodeID, s.Leaf, s.Challenge)
	return identity.Verify(message, proof, connectKey, s.Profile)
}

// proofMessage is what the CONNECT proof signs: the label, a zero byte, the
// nonce, the station's and the client's node_ids, the SHA-384 of the leaf DER
// and the SHA-384 of the challenge bytes as received.
func proofMessage(nonce []byte, stationNodeID, clientNodeID [32]byte, leafDER, challenge []byte) []byte {
	leafHash, challengeHash := sha512.Sum384(leafDER), sha512.Sum384(challenge)
	out := make([]byte, 0, len(connectProofLabel)+1+len(nonce)+2*32+2*48)
	out = append(out, connectProofLabel...)
	out = append(out, 0)
	out = append(out, nonce...)
	out = append(out, stationNodeID[:]...)
	out = append(out, clientNodeID[:]...)
	out = append(out, leafHash[:]...)
	return append(out, challengeHash[:]...)
}

func wireRefusal(err error) RefusalCode {
	switch {
	case errors.Is(err, ErrUnsupportedVersion):
		return RefusalUnsupportedVersion
	case errors.Is(err, ErrPuzzleInvalid):
		return RefusalPuzzleInvalid
	default:
		return RefusalNotAccepted
	}
}

func helloAccepted(capabilities uint64) []byte {
	return encodeFrame("hello", entry("accepted", cbor.Int(1)), entry("capabilities", cbor.Uint64(capabilities)))
}

func helloRefused(code RefusalCode, capabilities uint64) []byte {
	return encodeFrame("hello",
		entry("accepted", cbor.Int(0)),
		entry("refusal_code", cbor.Text(string(code))),
		entry("capabilities", cbor.Uint64(capabilities)))
}

// ReadHello is the client's reading of HELLO: the station's capability bits,
// or a *RefusedError with its refusal code.
func ReadHello(frame []byte) (uint64, error) {
	f, err := decode(frame, "hello", helloAcceptedKeys, helloRefusedKeys)
	if err != nil {
		return 0, err
	}
	accepted, _ := f["accepted"].AsInt64()
	_, hasCode := f["refusal_code"]
	switch {
	case accepted == 1 && !hasCode:
		return f.uint("capabilities"), nil
	case accepted == 0 && hasCode:
		return 0, &RefusedError{Code: RefusalCode(f.text("refusal_code"))}
	default:
		return 0, ErrMalformedFrame
	}
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
func ReadStatus(frame []byte, p Peer) (int64, error) {
	f, err := decode(frame, "status", statusKeys)
	if err != nil {
		return 0, err
	}
	return identity.VerifyStatus(f.signed("statement"), p.Binding, p.IdentityKey, p.Profile, p.NowMs)
}

// frameFields is a decoded handshake frame's values by their keys.
type frameFields map[string]cbor.Value

// decode reads a handshake frame strictly, in macula's order: the decoding
// rule, the version, the frame type, exactly the keys of one of the layouts,
// then the type and length of every field.
func decode(frame []byte, frameType string, layouts ...[]string) (frameFields, error) {
	v, err := cbor.Decode(frame)
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
	if err := f.checkVersion(); err != nil {
		return nil, err
	}
	if err := f.checkFrameType(frameType); err != nil {
		return nil, err
	}
	if nonText > 0 || !f.hasLayout(layouts) || !f.typed() {
		return nil, ErrMalformedFrame
	}
	return f, nil
}

func (f frameFields) checkVersion() error {
	version, isInt := f["version"].AsInt64()
	switch {
	case !isInt:
		return ErrMalformedFrame
	case version != Version:
		return ErrUnsupportedVersion
	}
	return nil
}

func (f frameFields) checkFrameType(expected string) error {
	frameType, isText := f["frame_type"].AsText()
	switch {
	case !isText:
		return ErrMalformedFrame
	case frameType != expected:
		return ErrUnexpectedFrame
	}
	return nil
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
	case "nonce":
		nonce, isBytes := v.AsBytes()
		return isBytes && len(nonce) == nonceSize
	case "identity_key", "connect_key", "proof", "member_endorsement":
		_, isBytes := v.AsBytes()
		return isBytes
	case "tls_binding", "tls_status", "connect_binding", "connect_status", "statement":
		_, err := identity.ParseSignedTBS(v)
		return err == nil
	case "capabilities":
		n, isInt := v.AsInt64()
		return isInt && n >= 0 && n < maxProtocolInt
	case "accepted":
		n, isInt := v.AsInt64()
		return isInt && (n == 0 || n == 1)
	case "refusal_code":
		code, isText := v.AsText()
		return isText && knownRefusal(RefusalCode(code))
	default:
		return false
	}
}

func knownRefusal(code RefusalCode) bool {
	return code == RefusalUnsupportedVersion || code == RefusalPuzzleInvalid || code == RefusalNotAccepted
}

func (f frameFields) bytes(key string) []byte {
	b, _ := f[key].AsBytes()
	return b
}

func (f frameFields) text(key string) string {
	s, _ := f[key].AsText()
	return s
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
	all := append([]cbor.MapEntry{
		entry("version", cbor.Int(Version)),
		entry("frame_type", cbor.Text(frameType)),
	}, entries...)
	return cbor.Encode(cbor.Map(all))
}

func entry(key string, v cbor.Value) cbor.MapEntry {
	return cbor.MapEntry{Key: cbor.Text(key), Val: v}
}
