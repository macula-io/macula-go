package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/frame"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// The handshake as wire 1.0 freezes it (macula docs/design/WIRE_1_0.md section
// 4): version 5 alone, negotiated ranges, proof V3 over the CONNECT tbs, and
// the session proof. macula's transcripts run in
// wire_1_0_handshake_vectors_test.go; these cases build both sides here.

const (
	now                 = int64(1789000000000)
	minute              = int64(60000)
	hour                = 60 * minute
	day                 = 24 * hour
	stationCapabilities = uint64(5)
	clientCapabilities  = uint64(2)
	mldsaSignatureBytes = 4627
)

var leaf = []byte("the strict DER leaf the station presented")

// world is what both sides of a handshake hold in one profile.
type world struct {
	profile        profile.Profile
	station        *identity.NodeKey
	client         *identity.NodeKey
	connect        *identity.NodeKey
	tlsBinding     identity.SignedTBS
	tlsStatus      identity.SignedTBS
	connectBinding identity.SignedTBS
	connectStatus  identity.SignedTBS
}

// worlds are made once per profile: RSA-4096 keys take seconds to generate.
var worlds = map[profile.Profile]func() (*world, error){
	profile.PQPure:   sync.OnceValues(func() (*world, error) { return newWorld(profile.PQPure) }),
	profile.PQHybrid: sync.OnceValues(func() (*world, error) { return newWorld(profile.PQHybrid) }),
}

func newWorld(p profile.Profile) (*world, error) {
	w := &world{profile: p}
	var err error
	if w.station, err = identity.GenerateKey(identity.PurposeIdentity, p); err != nil {
		return nil, err
	}
	if w.client, err = identity.GenerateKey(identity.PurposeIdentity, p); err != nil {
		return nil, err
	}
	if w.connect, err = identity.GenerateKey(identity.PurposeConnect, p); err != nil {
		return nil, err
	}
	if w.tlsBinding, err = identity.TLSBinding(w.station, leaf, now, now+7*day); err != nil {
		return nil, err
	}
	if w.tlsStatus, err = identity.StatusStatement(w.station, w.tlsBinding, now, now+hour); err != nil {
		return nil, err
	}
	if w.connectBinding, err = identity.ConnectBinding(w.client, w.connect.PublicKey(), now, now+day); err != nil {
		return nil, err
	}
	w.connectStatus, err = identity.StatusStatement(w.client, w.connectBinding, now, now+hour)
	return w, err
}

func forEachWorld(t *testing.T, run func(t *testing.T, w *world)) {
	for _, p := range []profile.Profile{profile.PQPure, profile.PQHybrid} {
		t.Run(string(p), func(t *testing.T) {
			w, err := worlds[p]()
			if err != nil {
				t.Fatalf("world: %v", err)
			}
			run(t, w)
		})
	}
}

// exporterOf stands in for one TLS session's exporter: the same label, context
// and length give the same bytes on both ends, and another session gives other
// bytes.
func exporterOf(session string) Exporter {
	return func(label string, context []byte, length int) ([]byte, error) {
		if label != ExporterLabel {
			return nil, errors.New("unexpected exporter label " + label)
		}
		return exported(session, context)[:length], nil
	}
}

func exported(session string, context []byte) []byte {
	mac := hmac.New(sha256.New, []byte(session))
	mac.Write([]byte(ExporterLabel))
	mac.Write(context)
	return mac.Sum(nil)
}

func (w *world) ranges() Ranges { return Supported(w.profile) }

// negotiated is what the station chose from this client's opener.
func (w *world) negotiated(t *testing.T) Negotiated {
	t.Helper()
	n, hello, err := ReadOpener(Opener(w.ranges()), w.ranges())
	if err != nil || hello != nil {
		t.Fatalf("ReadOpener: %v (HELLO %x)", err, hello)
	}
	return n
}

func (w *world) stationMaterial() StationMaterial {
	return StationMaterial{Profile: w.profile, IdentityKey: w.station.PublicKey(), TLSBinding: w.tlsBinding, TLSStatus: w.tlsStatus}
}

func (w *world) clientSession() ClientSession {
	return ClientSession{
		Profile:        w.profile,
		ExpectedNodeID: identity.NodeIDOf(w.station.PublicKey(), w.profile),
		Leaf:           leaf,
		IdentityKey:    w.client.PublicKey(),
		ConnectKey:     w.connect,
		ConnectBinding: w.connectBinding,
		ConnectStatus:  w.connectStatus,
		Capabilities:   clientCapabilities,
		NowMs:          now + minute,
		Export:         exporterOf("session_a"),
	}
}

func (w *world) stationSession(t *testing.T, challenge []byte) StationSession {
	return StationSession{
		Profile:          w.profile,
		Negotiated:       w.negotiated(t),
		Challenge:        challenge,
		Leaf:             leaf,
		PuzzleDifficulty: 0,
		PuzzleMode:       PuzzleModeEnforce,
		Capabilities:     stationCapabilities,
		NowMs:            now + minute,
		Export:           exporterOf("session_a"),
		SignSessionProof: func(_ [32]byte, message []byte) ([]byte, error) { return w.station.Sign(message) },
	}
}

func (w *world) challenge(t *testing.T) []byte {
	t.Helper()
	challenge, err := Challenge(w.stationMaterial(), w.negotiated(t), w.ranges())
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	return challenge
}

func (w *world) connectFor(t *testing.T, challenge []byte) []byte {
	t.Helper()
	connect, _, err := AnswerChallenge(challenge, w.clientSession())
	if err != nil {
		t.Fatalf("AnswerChallenge: %v", err)
	}
	return connect
}

// pair is a whole handshake: the challenge, CONNECT, the station as the client
// holds it, the client as the station holds it, and HELLO.
func (w *world) pair(t *testing.T) (challenge, connect []byte, station Station, client Client, hello []byte) {
	t.Helper()
	challenge = w.challenge(t)
	connect, station, err := AnswerChallenge(challenge, w.clientSession())
	if err != nil {
		t.Fatalf("AnswerChallenge: %v", err)
	}
	client, hello, err = AcceptConnect(connect, w.stationSession(t, challenge))
	if err != nil {
		t.Fatalf("AcceptConnect: %v", err)
	}
	return challenge, connect, station, client, hello
}

// sessionMessage is the session proof's message for this challenge and
// CONNECT under session's exporter, as the station signs it.
func (w *world) sessionMessage(challenge, connect []byte, session string) []byte {
	stationID := identity.NodeIDOf(w.station.PublicKey(), w.profile)
	clientID := identity.NodeIDOf(w.client.PublicKey(), w.profile)
	challengeHash, connectHash := sha512.Sum384(challenge), sha512.Sum384(connect)
	return concat([]byte(sessionProofLabel), []byte{0}, exported(session, concat(clientID[:], stationID[:])),
		challengeHash[:], connectHash[:], stationID[:], clientID[:], binary.BigEndian.AppendUint64(nil, stationCapabilities))
}

func otherProfile(p profile.Profile) profile.Profile {
	if p == profile.PQPure {
		return profile.PQHybrid
	}
	return profile.PQPure
}

// fields is a frame's values by their text keys.
func fields(t *testing.T, frame []byte) map[string]cbor.Value {
	t.Helper()
	v, err := cbor.Decode(frame)
	if err != nil {
		t.Fatalf("decode frame: %v", err)
	}
	entries, _ := v.AsMap()
	out := make(map[string]cbor.Value, len(entries))
	for _, e := range entries {
		key, _ := e.Key.AsText()
		out[key] = e.Val
	}
	return out
}

func encodeFields(f map[string]cbor.Value) []byte {
	entries := make([]cbor.MapEntry, 0, len(f))
	for key, v := range f {
		entries = append(entries, cbor.MapEntry{Key: cbor.Text(key), Val: v})
	}
	return cbor.Encode(cbor.Map(entries))
}

// rebuilt is frame with fields replaced or added.
func rebuilt(t *testing.T, frame []byte, changes map[string]cbor.Value) []byte {
	t.Helper()
	f := fields(t, frame)
	for key, v := range changes {
		f[key] = v
	}
	return encodeFields(f)
}

func without(t *testing.T, frame []byte, key string) []byte {
	t.Helper()
	f := fields(t, frame)
	delete(f, key)
	return encodeFields(f)
}

// withDuplicateKey is frame with a second copy of one key, which only a
// hand-built encoding can carry.
func withDuplicateKey(t *testing.T, frame []byte, key string) []byte {
	t.Helper()
	f := fields(t, frame)
	out := []byte{0xa0 + byte(len(f)+1)}
	for k, v := range f {
		out = append(out, cbor.Encode(cbor.Text(k))...)
		out = append(out, cbor.Encode(v)...)
	}
	out = append(out, cbor.Encode(cbor.Text(key))...)
	return append(out, cbor.Encode(f[key])...)
}

// withIntegerKey is frame with one more entry under an integer key, which no
// handshake frame has.
func withIntegerKey(t *testing.T, frame []byte) []byte {
	t.Helper()
	f := fields(t, frame)
	entries := make([]cbor.MapEntry, 0, len(f)+1)
	for key, v := range f {
		entries = append(entries, cbor.MapEntry{Key: cbor.Text(key), Val: v})
	}
	entries = append(entries, cbor.MapEntry{Key: cbor.Uint64(1), Val: cbor.Null()})
	return cbor.Encode(cbor.Map(entries))
}

func frameKeys(t *testing.T, frame []byte) string {
	t.Helper()
	keys := make([]string, 0)
	for key := range fields(t, frame) {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	return strings.Join(keys, " ")
}

// leafWith stands in for a certificate whose public key info holds a key's
// ML-DSA-87 half.
func leafWith(key []byte) []byte {
	out := append([]byte("certificate before the key"), key[:2592]...)
	return append(out, "certificate after the key"...)
}

// nearCopy is key's ML-DSA-87 half with its last byte changed, followed by
// other's classical half.
func nearCopy(key, other []byte) []byte {
	out := bytes.Clone(key[:2592])
	out[2591] ^= 1
	return append(out, other[2592:]...)
}

func leadingZeroBits(id [32]byte) int {
	for n := 0; n < 256; n++ {
		if id[n/8]>>(7-n%8)&1 == 1 {
			return n
		}
	}
	return 256
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// checkRefused fails t unless err is want and the HELLO bytes refuse with code.
func checkRefused(t *testing.T, name string, hello []byte, err, want error, code RefusalCode) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Errorf("%s: %v, want %v", name, err, want)
	}
	_, helloErr := ReadHello(hello, Station{})
	var refused *RefusedError
	if !errors.As(helloErr, &refused) || refused.Code != code {
		t.Errorf("%s: the HELLO reads as %v, want a refusal with %s", name, helloErr, code)
	}
}

func TestAWholeHandshakeConnectsBothSides(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge, connect, station, client, hello := w.pair(t)
		if station.NodeID != identity.NodeIDOf(w.station.PublicKey(), w.profile) ||
			!bytes.Equal(station.IdentityKey, w.station.PublicKey()) ||
			station.StatusExpiresAt != now+hour || station.BindingNotAfter != now+7*day || station.Version != Version {
			t.Errorf("the station as the client sees it: node_id %x, status until %d, binding until %d, version %d",
				station.NodeID, station.StatusExpiresAt, station.BindingNotAfter, station.Version)
		}
		if client.NodeID != identity.NodeIDOf(w.client.PublicKey(), w.profile) ||
			!bytes.Equal(client.IdentityKey, w.client.PublicKey()) || !bytes.Equal(client.ConnectKey, w.connect.PublicKey()) ||
			client.Capabilities != clientCapabilities || client.StatusExpiresAt != now+hour ||
			client.BindingNotAfter != now+day || client.Puzzle != PuzzleResultSolved || client.Version != Version {
			t.Errorf("the client as the station sees it: node_id %x, capabilities %d, status until %d, binding until %d, puzzle %s, version %d",
				client.NodeID, client.Capabilities, client.StatusExpiresAt, client.BindingNotAfter, client.Puzzle, client.Version)
		}
		if capabilities, err := ReadHello(hello, station); err != nil || capabilities != stationCapabilities {
			t.Errorf("ReadHello = (%d, %v), want the station's capabilities", capabilities, err)
		}
		for name, frame := range map[string][]byte{"opener": Opener(w.ranges()), "challenge": challenge, "CONNECT": connect, "HELLO": hello} {
			if version, _ := fields(t, frame)["version"].AsInt64(); version != 5 {
				t.Errorf("the %s is version %d, want 5", name, version)
			}
		}
		if keys := frameKeys(t, Opener(w.ranges())); keys != "frame_type profiles version versions" {
			t.Errorf("the opener holds %q", keys)
		}
		if keys := frameKeys(t, challenge); keys != "frame_type identity_key nonce profile profiles tls_binding tls_status version versions" {
			t.Errorf("the challenge holds %q", keys)
		}
		if keys := frameKeys(t, connect); keys != "capabilities connect_binding connect_key connect_status frame_type identity_key member_endorsement profile profiles proof version versions" {
			t.Errorf("CONNECT holds %q", keys)
		}
		if keys := frameKeys(t, hello); keys != "accepted capabilities frame_type session_proof version" {
			t.Errorf("HELLO holds %q", keys)
		}
		if endorsement, ok := fields(t, connect)["member_endorsement"].AsBytes(); !ok || len(endorsement) != 0 {
			t.Errorf("CONNECT's member_endorsement %x (bytes %t), want it present and empty", endorsement, ok)
		}
		if client.MemberEndorsement == nil || len(client.MemberEndorsement) != 0 {
			t.Errorf("the station was handed member_endorsement %x, want an empty one", client.MemberEndorsement)
		}
		if bytes.Equal(challenge, w.challenge(t)) {
			t.Error("two challenges are equal, want a fresh nonce in each")
		}
	})
}

// Version 5 is wire 1.0's only handshake version: a handshake version bump is a
// wire major.
func TestTheHandshakeIsVersion5Only(t *testing.T) {
	if Version != 5 {
		t.Fatalf("Version = %d, want 5", Version)
	}
	if r := Supported(profile.PQPure); r.MinVersion != 5 || r.MaxVersion != 5 || !slices.Equal(r.Profiles, []profile.Profile{profile.PQPure}) {
		t.Errorf("Supported = %+v, want versions [5, 5] and pq_pure", r)
	}
}

// The station picks the highest version in both ranges and the first profile
// in the client's list it supports; ranges that share no version, or lists no
// profile, are refused at once with a HELLO naming the station's ranges
// (WIRE_1_0.md sections 4.1 and 4.4).
func TestAStationNegotiatesFromTheOpener(t *testing.T) {
	station := Ranges{MinVersion: 5, MaxVersion: 5, Profiles: []profile.Profile{profile.PQPure, profile.PQHybrid}}
	n, hello, err := ReadOpener(Opener(Ranges{MinVersion: 4, MaxVersion: 6, Profiles: []profile.Profile{profile.PQHybrid, profile.PQPure}}), station)
	if err != nil || hello != nil || n.Version != 5 || n.Profile != profile.PQHybrid {
		t.Errorf("ReadOpener = (%+v, %x, %v), want version 5 and the client's first profile, pq_hybrid", n, hello, err)
	}
	for name, c := range map[string]struct {
		client Ranges
		want   error
		code   RefusalCode
	}{
		"no common version": {Ranges{MinVersion: 6, MaxVersion: 7, Profiles: []profile.Profile{profile.PQPure}}, ErrUnsupportedVersion, RefusalUnsupportedVersion},
		"no common profile": {Ranges{MinVersion: 5, MaxVersion: 5, Profiles: []profile.Profile{"example_profile"}}, ErrProfileUnsupported, RefusalProfileUnsupported},
	} {
		_, hello, err := ReadOpener(Opener(c.client), station)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
		_, readErr := ReadHello(hello, Station{})
		var refused *RefusedError
		if !errors.As(readErr, &refused) || refused.Code != c.code || refused.StationRanges == nil || !sameRanges(*refused.StationRanges, station) {
			t.Errorf("%s: the HELLO reads %v, want %s naming the station's ranges", name, readErr, c.code)
		}
	}
	v4 := encodeFrameVersion(4, "opener")
	if _, hello, err := ReadOpener(v4, station); !errors.Is(err, ErrUnsupportedVersion) || hello == nil {
		t.Errorf("a version 4 opener: (HELLO %x, %v), want unsupported_version with a HELLO", hello, err)
	}
	for name, opener := range map[string][]byte{
		"no versions":       without(t, Opener(Supported(profile.PQPure)), "versions"),
		"versions reversed": rebuilt(t, Opener(Supported(profile.PQPure)), map[string]cbor.Value{"versions": cbor.List([]cbor.Value{cbor.Int(6), cbor.Int(5)})}),
		"nine profiles": rebuilt(t, Opener(Supported(profile.PQPure)), map[string]cbor.Value{"profiles": cbor.List([]cbor.Value{
			cbor.Text("a"), cbor.Text("b"), cbor.Text("c"), cbor.Text("d"), cbor.Text("e"), cbor.Text("f"), cbor.Text("g"), cbor.Text("h"), cbor.Text("i")})}),
		"a profile twice": rebuilt(t, Opener(Supported(profile.PQPure)), map[string]cbor.Value{"profiles": cbor.List([]cbor.Value{cbor.Text("pq_pure"), cbor.Text("pq_pure")})}),
	} {
		if _, hello, err := ReadOpener(opener, station); !errors.Is(err, ErrMalformedFrame) || hello != nil {
			t.Errorf("%s: (HELLO %x, %v), want malformed_frame and no HELLO", name, hello, err)
		}
	}
}

// A client finds a downgrade itself: the chosen version and profile must be
// the highest common ones of its own ranges and the station's repeated ranges,
// which the session proof then covers.
func TestAClientRefusesAChallengeThatDowngradesTheNegotiation(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		both := []profile.Profile{otherProfile(w.profile), w.profile}
		session := w.clientSession()
		session.Ranges = Ranges{MinVersion: 5, MaxVersion: 5, Profiles: both}
		widened := rebuilt(t, challenge, map[string]cbor.Value{"profiles": cbor.List([]cbor.Value{
			cbor.Text(string(both[0])), cbor.Text(string(both[1]))})})
		if _, err := ReadChallenge(widened, session); !errors.Is(err, ErrDowngradeDetected) {
			t.Errorf("the client's first profile shared, %s chosen: %v, want ErrDowngradeDetected", w.profile, err)
		}
		if _, err := ReadChallenge(rebuilt(t, challenge, map[string]cbor.Value{"profile": cbor.Text(string(otherProfile(w.profile)))}),
			w.clientSession()); !errors.Is(err, ErrDowngradeDetected) {
			t.Errorf("a profile the client never offered: %v, want ErrDowngradeDetected", err)
		}
		floored := w.clientSession()
		floored.Floor = func([32]byte) int64 { return 6 }
		if _, err := ReadChallenge(challenge, floored); !errors.Is(err, ErrVersionBelowFloor) {
			t.Errorf("a floor of 6 for this station: %v, want ErrVersionBelowFloor", err)
		}
	})
}

// A CONNECT carries the endorsement the session was given, and the station is
// handed it untouched. Nothing checks it here: enforcing it is the station's.
func TestAConnectCarriesTheSessionsEndorsementAndTheStationIsHandedIt(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		session := w.clientSession()
		session.MemberEndorsement = []byte("a signed membership endorsement")
		connect, _, err := AnswerChallenge(challenge, session)
		if err != nil {
			t.Fatalf("AnswerChallenge: %v", err)
		}
		client, _, err := AcceptConnect(connect, w.stationSession(t, challenge))
		if err != nil {
			t.Fatalf("AcceptConnect: %v", err)
		}
		if !bytes.Equal(client.MemberEndorsement, session.MemberEndorsement) {
			t.Errorf("the station was handed %q, want %q", client.MemberEndorsement, session.MemberEndorsement)
		}
	})
}

// Proof V3 covers the CONNECT tbs, so every field CONNECT carries is covered:
// an endorsement, capabilities or ranges changed after signing fail the proof
// (WIRE_1_0.md section 4.2, A1).
func TestTheProofCoversEveryConnectField(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		for name, changed := range map[string][]byte{
			"an endorsement swapped in after signing": rebuilt(t, connect, map[string]cbor.Value{"member_endorsement": cbor.Bytes([]byte("swapped in after signing"))}),
			"capabilities changed after signing":      rebuilt(t, connect, map[string]cbor.Value{"capabilities": cbor.Int(int64(clientCapabilities) + 1)}),
		} {
			_, hello, err := AcceptConnect(changed, w.stationSession(t, challenge))
			checkRefused(t, name, hello, err, ErrProofInvalid, RefusalNotAccepted)
		}
	})
}

// Proof V3 signs label || 0x00 || nonce || station node_id || client node_id ||
// SHA-384(leaf) || SHA-384(challenge) || E || SHA-384(CONNECT tbs), with the
// CONNECT key, the tbs being CONNECT with proof as the empty byte string.
func TestTheProofV3SignsWhatTheDesignSays(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		nonce, _ := fields(t, challenge)["nonce"].AsBytes()
		proof, _ := fields(t, connect)["proof"].AsBytes()
		stationID := identity.NodeIDOf(w.station.PublicKey(), w.profile)
		clientID := identity.NodeIDOf(w.client.PublicKey(), w.profile)
		leafHash, challengeHash := sha512.Sum384(leaf), sha512.Sum384(challenge)
		tbsHash := sha512.Sum384(rebuilt(t, connect, map[string]cbor.Value{"proof": cbor.Bytes(nil)}))
		e := exported("session_a", concat(clientID[:], stationID[:]))
		message := concat([]byte("MACULA-PQ-CONNECT-PROOF-V3"), []byte{0}, nonce, stationID[:], clientID[:], leafHash[:], challengeHash[:], e, tbsHash[:])
		if !identity.Verify(message, proof, w.connect.PublicKey(), w.profile) {
			t.Fatal("the proof does not verify over the design's message with the CONNECT key")
		}
	})
}

// The client checks every part of the challenge before it signs, and a refused
// challenge produces no CONNECT.
func TestAClientRefusesAChallengeItCannotTrust(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		answer := func(change func(*ClientSession)) error {
			session := w.clientSession()
			change(&session)
			connect, _, err := AnswerChallenge(challenge, session)
			if err != nil && connect != nil {
				t.Errorf("a refused challenge produced CONNECT bytes")
			}
			return err
		}

		var wrong [32]byte
		wrong[31] = 1
		err := answer(func(s *ClientSession) { s.ExpectedNodeID = wrong })
		var mismatch *PeerIdentityMismatchError
		if !errors.As(err, &mismatch) || !errors.Is(err, ErrPeerIdentityMismatch) ||
			mismatch.Expected != wrong || mismatch.Derived != identity.NodeIDOf(w.station.PublicKey(), w.profile) {
			t.Errorf("another expected node_id: %v, want a peer identity mismatch naming both node_ids", err)
		}

		cases := []struct {
			name   string
			change func(*ClientSession)
			want   error
		}{
			{"a leaf this handshake never saw", func(s *ClientSession) { s.Leaf = []byte("a leaf this handshake never saw") }, identity.ErrBindingKeyMismatch},
			{"two hours on", func(s *ClientSession) { s.NowMs = now + 2*hour }, identity.ErrStatusExpired},
			{"an hour before the binding", func(s *ClientSession) { s.NowMs = now - hour }, identity.ErrBindingNotYetValid},
			{"a leaf that carries the station's identity key", func(s *ClientSession) { s.Leaf = leafWith(w.station.PublicKey()) }, ErrKeyPurposeReuse},
			{"a leaf that carries this client's CONNECT key", func(s *ClientSession) { s.Leaf = leafWith(w.connect.PublicKey()) }, ErrKeyPurposeReuse},
			{"a CONNECT key that is the identity key", func(s *ClientSession) { s.ConnectKey = w.client }, ErrKeyPurposeReuse},
			{"a leaf key one byte from the station's key", func(s *ClientSession) {
				s.Leaf = leafWith(nearCopy(w.station.PublicKey(), w.connect.PublicKey()))
			}, identity.ErrBindingKeyMismatch},
			{"no TLS exporter", func(s *ClientSession) { s.Export = nil }, ErrExporterUnavailable},
		}
		for _, c := range cases {
			if err := answer(c.change); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
		if _, _, err := AnswerChallenge(Opener(w.ranges()), w.clientSession()); !errors.Is(err, ErrUnexpectedFrame) {
			t.Errorf("an opener in place of the challenge: %v, want ErrUnexpectedFrame", err)
		}
	})
}

func TestAClientRefusesAChallengeThatDoesNotDecodeExactly(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		stationKey := w.station.PublicKey()
		cases := []struct {
			name  string
			frame []byte
			want  error
		}{
			{"a trailing byte", append(bytes.Clone(challenge), 0), ErrMalformedFrame},
			{"bytes that are not CBOR", []byte("not cbor"), ErrMalformedFrame},
			{"a duplicate nonce", withDuplicateKey(t, challenge, "nonce"), ErrMalformedFrame},
			{"an unknown key", rebuilt(t, challenge, map[string]cbor.Value{"comment": cbor.Text("x")}), ErrMalformedFrame},
			{"no TLS status", without(t, challenge, "tls_status"), ErrMalformedFrame},
			{"no ranges", without(t, without(t, challenge, "versions"), "profiles"), ErrMalformedFrame},
			{"a 31-byte nonce", rebuilt(t, challenge, map[string]cbor.Value{"nonce": cbor.Bytes(make([]byte, 31))}), ErrMalformedFrame},
			{"the profile as bytes", rebuilt(t, challenge, map[string]cbor.Value{"profile": cbor.Bytes([]byte(w.profile))}), ErrMalformedFrame},
			{"a TLS binding without its signature", rebuilt(t, challenge, map[string]cbor.Value{
				"tls_binding": cbor.Map([]cbor.MapEntry{{Key: cbor.Text("tbs"), Val: cbor.Bytes(nil)}}),
			}), ErrMalformedFrame},
			{"a station key one byte short", rebuilt(t, challenge, map[string]cbor.Value{"identity_key": cbor.Bytes(stationKey[:len(stationKey)-1])}), ErrMalformedFrame},
			{"version 4", rebuilt(t, challenge, map[string]cbor.Value{"version": cbor.Int(4)}), ErrUnsupportedVersion},
			{"a non-text map key", withIntegerKey(t, challenge), ErrMalformedFrame},
		}
		if w.profile == profile.PQHybrid {
			garbage := append(bytes.Clone(stationKey[:2592]), bytes.Repeat([]byte{0x30}, len(stationKey)-2592)...)
			cases = append(cases, struct {
				name  string
				frame []byte
				want  error
			}{"an RSA half that is not a canonical DER key", rebuilt(t, challenge, map[string]cbor.Value{"identity_key": cbor.Bytes(garbage)}), ErrMalformedFrame})
		}
		for _, c := range cases {
			if _, _, err := AnswerChallenge(c.frame, w.clientSession()); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
	})
}

// A refusing station tells the client only one coarse code, whatever failed.
func TestAStationRefusesAConnectItCannotTrustWithOneCoarseCode(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		otherChallenge := w.challenge(t)
		clientKey, connectKey, stationKey := w.client.PublicKey(), w.connect.PublicKey(), w.station.PublicKey()
		withConnectKey := func(key []byte) []byte {
			return rebuilt(t, connect, map[string]cbor.Value{"connect_key": cbor.Bytes(key)})
		}
		aheadOfStation, err := identity.StatusStatement(w.client, w.connectBinding, now+7*minute, now+67*minute)
		if err != nil {
			t.Fatalf("StatusStatement: %v", err)
		}
		type refusal struct {
			name   string
			frame  []byte
			change func(*StationSession)
			want   error
			code   RefusalCode
		}
		cases := []refusal{
			{"a leaf never presented", connect, func(s *StationSession) { s.Leaf = []byte("a leaf never presented") }, ErrProofInvalid, RefusalNotAccepted},
			{"another challenge", connect, func(s *StationSession) { s.Challenge = otherChallenge }, ErrProofInvalid, RefusalNotAccepted},
			{"another session's E", connect, func(s *StationSession) { s.Export = exporterOf("session_b") }, ErrProofInvalid, RefusalNotAccepted},
			{"the station's key as the CONNECT key", withConnectKey(stationKey), nil, identity.ErrBindingKeyMismatch, RefusalNotAccepted},
			{"the identity key as the CONNECT key", withConnectKey(clientKey), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
			{"the CONNECT key in the presented leaf", connect, func(s *StationSession) { s.Leaf = leafWith(connectKey) }, ErrKeyPurposeReuse, RefusalNotAccepted},
			{"a CONNECT key one byte from the identity key", withConnectKey(nearCopy(clientKey, connectKey)), nil, identity.ErrBindingKeyMismatch, RefusalNotAccepted},
			{"two hours on", connect, func(s *StationSession) { s.NowMs = now + 2*hour }, identity.ErrStatusExpired, RefusalNotAccepted},
			{"an opener", Opener(w.ranges()), nil, ErrUnexpectedFrame, RefusalNotAccepted},
			{"version 4", rebuilt(t, connect, map[string]cbor.Value{"version": cbor.Int(4)}), nil, ErrUnsupportedVersion, RefusalUnsupportedVersion},
			{"ranges other than the opener's", rebuilt(t, connect, map[string]cbor.Value{"versions": cbor.List([]cbor.Value{cbor.Int(5), cbor.Int(6)})}), nil, ErrNegotiationMismatch, RefusalNotAccepted},
			{"a profile the station did not choose", rebuilt(t, connect, map[string]cbor.Value{"profile": cbor.Text(string(otherProfile(w.profile)))}), nil, ErrProfileUnsupported, RefusalNotAccepted},
			{"a floor of 6 for this client", connect, func(s *StationSession) { s.Floor = func([32]byte) int64 { return 6 } }, ErrVersionBelowFloor, RefusalNotAccepted},
			{"bytes that are not CBOR", []byte("not cbor"), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"an 8-byte proof", rebuilt(t, connect, map[string]cbor.Value{"proof": cbor.Bytes(make([]byte, 8))}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"an identity key one byte short", rebuilt(t, connect, map[string]cbor.Value{"identity_key": cbor.Bytes(clientKey[:len(clientKey)-1])}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"a CONNECT key one byte short", withConnectKey(connectKey[:len(connectKey)-1]), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"capabilities at 2^53", rebuilt(t, connect, map[string]cbor.Value{"capabilities": cbor.Int(1 << 53)}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"a proof of the right length that does not verify", rebuilt(t, connect, map[string]cbor.Value{"proof": cbor.Bytes(make([]byte, identity.SignatureSize(w.profile)))}), nil, ErrProofInvalid, RefusalNotAccepted},
			{"a CONNECT status issued 6 minutes ahead of the station", rebuilt(t, connect, map[string]cbor.Value{"connect_status": aheadOfStation.Value()}), nil, identity.ErrStatusFutureDated, RefusalNotAccepted},
			{"no TLS exporter", connect, func(s *StationSession) { s.Export = nil }, ErrExporterUnavailable, RefusalNotAccepted},
		}
		if w.profile == profile.PQHybrid {
			cases = append(cases,
				refusal{"a CONNECT key sharing the identity key's RSA half", withConnectKey(concat(connectKey[:2592], clientKey[2592:])), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
				refusal{"a CONNECT key sharing the identity key's ML-DSA half", withConnectKey(concat(clientKey[:2592], connectKey[2592:])), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
			)
		}
		for _, c := range cases {
			session := w.stationSession(t, challenge)
			if c.change != nil {
				c.change(&session)
			}
			_, hello, err := AcceptConnect(c.frame, session)
			checkRefused(t, c.name, hello, err, c.want, c.code)
		}
	})
}

// A CONNECT whose received bytes are not its own deterministic encoding is
// malformed, so the station rebuilds exactly the tbs the client signed.
func TestAConnectThatIsNotDeterministicCBORIsMalformed(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		f := fields(t, connect)
		reordered := []byte{0xa0 + byte(len(f))}
		keys := make([]string, 0, len(f))
		for key := range f {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		slices.Reverse(keys)
		for _, key := range keys {
			reordered = append(reordered, cbor.Encode(cbor.Text(key))...)
			reordered = append(reordered, cbor.Encode(f[key])...)
		}
		if bytes.Equal(reordered, connect) {
			t.Fatal("the reordering changed nothing")
		}
		_, hello, err := AcceptConnect(reordered, w.stationSession(t, challenge))
		checkRefused(t, "a CONNECT in another key order", hello, err, ErrMalformedFrame, RefusalNotAccepted)
	})
}

// The station checks the puzzle on the client's derived node_id before any
// signature: before the CONNECT binding, the status statement and the proof.
func TestAStationChecksThePuzzleBeforeAnySignature(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		solved := leadingZeroBits(identity.NodeIDOf(w.client.PublicKey(), w.profile))
		unsolved := solved + 1
		accept := func(mode PuzzleMode, difficulty int, change func(*StationSession)) (Client, []byte, error) {
			session := w.stationSession(t, challenge)
			session.PuzzleMode, session.PuzzleDifficulty = mode, difficulty
			if change != nil {
				change(&session)
			}
			return AcceptConnect(connect, session)
		}

		_, hello, err := accept(PuzzleModeEnforce, unsolved, nil)
		checkRefused(t, "enforce, unsolved", hello, err, ErrPuzzleInvalid, RefusalPuzzleInvalid)
		_, _, err = accept(PuzzleModeEnforce, unsolved, func(s *StationSession) { s.Leaf = []byte("a leaf never presented") })
		if !errors.Is(err, ErrPuzzleInvalid) {
			t.Errorf("enforce, unsolved, with a failing proof: %v, want the puzzle refusal first", err)
		}
		withStationKey := rebuilt(t, connect, map[string]cbor.Value{"connect_key": cbor.Bytes(w.station.PublicKey())})
		unsolvedSession := w.stationSession(t, challenge)
		unsolvedSession.PuzzleDifficulty = unsolved
		_, hello, err = AcceptConnect(withStationKey, unsolvedSession)
		checkRefused(t, "enforce, unsolved, with a CONNECT binding that would fail", hello, err, ErrPuzzleInvalid, RefusalPuzzleInvalid)
		_, hello, err = accept(PuzzleModeEnforce, unsolved, func(s *StationSession) { s.NowMs = now + 2*hour })
		checkRefused(t, "enforce, unsolved, with a status statement that has expired", hello, err, ErrPuzzleInvalid, RefusalPuzzleInvalid)
		for _, c := range []struct {
			mode       PuzzleMode
			difficulty int
			want       PuzzleResult
		}{
			{PuzzleModeEnforce, solved, PuzzleResultSolved},
			{PuzzleModeLogOnly, unsolved, PuzzleResultUnsolved},
			{PuzzleModeOff, unsolved, PuzzleResultNotChecked},
		} {
			client, _, err := accept(c.mode, c.difficulty, nil)
			if err != nil || client.Puzzle != c.want {
				t.Errorf("%s at difficulty %d: (%s, %v), want accepted as %s", c.mode, c.difficulty, client.Puzzle, err, c.want)
			}
		}
	})
}

// Sign after verify: a CONNECT that fails any check never reaches the signer.
// Past the budget the station refuses with session_proof_rate, on the wire too.
func TestAStationSignsTheSessionProofOnlyAfterEveryCheckAndWithinItsBudget(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect, station, err := AnswerChallenge(challenge, w.clientSession())
		if err != nil {
			t.Fatalf("AnswerChallenge: %v", err)
		}
		signed := 0
		watched := w.stationSession(t, challenge)
		watched.SignSessionProof = func(_ [32]byte, _ []byte) ([]byte, error) { signed++; return nil, ErrSessionProofRate }
		otherE := watched
		otherE.Export = exporterOf("session_b")
		if _, _, err := AcceptConnect(connect, otherE); !errors.Is(err, ErrProofInvalid) {
			t.Errorf("a bad proof: %v, want ErrProofInvalid", err)
		}
		lapsed := watched
		lapsed.NowMs = now + 2*hour
		if _, _, err := AcceptConnect(connect, lapsed); err == nil {
			t.Error("a lapsed status statement was accepted")
		}
		if signed != 0 {
			t.Fatalf("the signer ran %d times for CONNECTs that failed their checks", signed)
		}
		_, hello, err := AcceptConnect(connect, watched)
		if !errors.Is(err, ErrSessionProofRate) || signed != 1 {
			t.Errorf("past the budget: %v after %d signings, want ErrSessionProofRate after one", err, signed)
		}
		if _, readErr := ReadHello(hello, station); !isRefusal(readErr, RefusalSessionProofRate) {
			t.Errorf("the budget refusal reads as %v, want session_proof_rate", readErr)
		}
	})
}

func TestAClientRefusesAHelloThatDoesNotProveTheSession(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge, connect, station, _, hello := w.pair(t)
		otherKey, err := identity.GenerateKey(identity.PurposeIdentity, w.profile)
		if err != nil {
			t.Fatal(err)
		}
		overOtherE, _ := w.station.Sign(w.sessionMessage(challenge, connect, "session_b"))
		byOtherKey, _ := otherKey.Sign(w.sessionMessage(challenge, connect, "session_a"))
		_, _, _, _, otherConnection := w.pair(t)
		cases := []struct {
			name  string
			hello []byte
			want  error
		}{
			{"a session proof over another session's E", rebuilt(t, hello, map[string]cbor.Value{"session_proof": cbor.Bytes(overOtherE)}), ErrSessionProofInvalid},
			{"another connection's HELLO", otherConnection, ErrSessionProofInvalid},
			{"a session proof by another key", rebuilt(t, hello, map[string]cbor.Value{"session_proof": cbor.Bytes(byOtherKey)}), ErrSessionProofInvalid},
			{"no session proof", without(t, hello, "session_proof"), ErrSessionProofMissing},
			{"a session proof of the wrong length", rebuilt(t, hello, map[string]cbor.Value{"session_proof": cbor.Bytes([]byte{0, 1})}), ErrMalformedFrame},
			{"a version 4 HELLO", rebuilt(t, hello, map[string]cbor.Value{"version": cbor.Int(4)}), ErrUnsupportedVersion},
		}
		for _, c := range cases {
			if _, err := ReadHello(c.hello, station); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
	})
}

// The case D17 existed for: an attacker who can forge ML-DSA-87 but not
// RSA-PSS-4096. A session proof whose ML-DSA half is the station's own, valid,
// and whose RSA half is another key's, is refused.
func TestAHybridSessionProofWithAForeignRSAHalfIsRefused(t *testing.T) {
	w, err := worlds[profile.PQHybrid]()
	if err != nil {
		t.Fatalf("world: %v", err)
	}
	challenge, connect, station, _, hello := w.pair(t)
	otherKey, err := identity.GenerateKey(identity.PurposeIdentity, profile.PQHybrid)
	if err != nil {
		t.Fatal(err)
	}
	proof, _ := fields(t, hello)["session_proof"].AsBytes()
	foreign, err := otherKey.Sign(w.sessionMessage(challenge, connect, "session_a"))
	if err != nil {
		t.Fatal(err)
	}
	spliced := concat(proof[:mldsaSignatureBytes], foreign[mldsaSignatureBytes:])
	if bytes.Equal(spliced, proof) {
		t.Fatal("the splice changed nothing")
	}
	if _, err := ReadHello(rebuilt(t, hello, map[string]cbor.Value{"session_proof": cbor.Bytes(spliced)}), station); !errors.Is(err, ErrSessionProofInvalid) {
		t.Errorf("a foreign RSA half: %v, want ErrSessionProofInvalid", err)
	}
}

func TestAClientReadsHelloExactly(t *testing.T) {
	hello := func(changes map[string]cbor.Value) []byte {
		f := map[string]cbor.Value{"version": cbor.Int(5), "frame_type": cbor.Text("hello"), "capabilities": cbor.Int(0)}
		for key, v := range changes {
			f[key] = v
		}
		return encodeFields(f)
	}
	refusing := func(code string) map[string]cbor.Value {
		return map[string]cbor.Value{"accepted": cbor.Int(0), "refusal_code": cbor.Text(code)}
	}
	_, err := ReadHello(hello(refusing("puzzle_invalid")), Station{})
	var refused *RefusedError
	if !errors.As(err, &refused) || !errors.Is(err, ErrRefused) || refused.Code != RefusalPuzzleInvalid || refused.StationRanges != nil {
		t.Errorf("a refusing HELLO: %v, want a refusal with puzzle_invalid naming no ranges", err)
	}
	acceptedWithCode := refusing("not_accepted")
	acceptedWithCode["accepted"] = cbor.Int(1)
	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"a refusal code that is not text", hello(map[string]cbor.Value{"accepted": cbor.Int(0), "refusal_code": cbor.Int(1)}), ErrMalformedFrame},
		{"an empty refusal code", hello(refusing("")), ErrMalformedFrame},
		{"a refusal without a code", hello(map[string]cbor.Value{"accepted": cbor.Int(0)}), ErrMalformedFrame},
		{"an acceptance with a refusal code", hello(acceptedWithCode), ErrMalformedFrame},
		{"accepted 2", hello(map[string]cbor.Value{"accepted": cbor.Int(2)}), ErrMalformedFrame},
		{"an acceptance without a session proof", hello(map[string]cbor.Value{"accepted": cbor.Int(1)}), ErrSessionProofMissing},
		{"capabilities at 2^53", hello(map[string]cbor.Value{"accepted": cbor.Int(1), "capabilities": cbor.Int(1 << 53)}), ErrMalformedFrame},
		{"an opener", Opener(Supported(profile.PQPure)), ErrUnexpectedFrame},
	}
	for _, c := range cases {
		if _, err := ReadHello(c.frame, Station{}); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}

func TestStatusFramesRenewAPeersStatement(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		statement, err := identity.StatusStatement(w.station, w.tlsBinding, now+15*minute, now+75*minute)
		if err != nil {
			t.Fatalf("StatusStatement: %v", err)
		}
		frame := StatusFrame(statement)
		peer := Peer{Profile: w.profile, IdentityKey: w.station.PublicKey(), Binding: w.tlsBinding, NowMs: now + 16*minute}
		if expiresAt, err := ReadStatus(frame, peer); err != nil || expiresAt != now+75*minute {
			t.Errorf("ReadStatus = (%d, %v), want the new statement's expiry", expiresAt, err)
		}
		other, err := identity.TLSBinding(w.station, leaf, now, now+day)
		if err != nil {
			t.Fatalf("TLSBinding: %v", err)
		}
		otherPeer := peer
		otherPeer.Binding = other
		if _, err := ReadStatus(frame, otherPeer); !errors.Is(err, identity.ErrStatusBindingMismatch) {
			t.Errorf("a statement for another binding: %v, want ErrStatusBindingMismatch", err)
		}
		early := peer
		early.NowMs = now + 9*minute
		if _, err := ReadStatus(frame, early); !errors.Is(err, identity.ErrStatusFutureDated) {
			t.Errorf("a statement issued more than 5 minutes ahead of the peer: %v, want ErrStatusFutureDated", err)
		}
		if _, err := ReadStatus(Opener(w.ranges()), peer); !errors.Is(err, ErrUnexpectedFrame) {
			t.Errorf("an opener in place of a status frame: %v, want ErrUnexpectedFrame", err)
		}
		if version, _ := fields(t, frame)["version"].AsInt64(); version != 5 {
			t.Errorf("status frame version %d, want 5", version)
		}
		v4 := encodeFrameVersion(4, "status", entry("statement", statement.Value()))
		if _, err := ReadStatus(v4, peer); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("a version 4 status frame: %v, want ErrUnsupportedVersion", err)
		}
	})
}

// A station session with a puzzle mode or difficulty the design does not have
// refuses every CONNECT, so a misconfigured station never admits a node
// unchecked.
func TestAStationSessionOutsideTheDesignRefusesEveryConnect(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		cases := []struct {
			name   string
			change func(*StationSession)
		}{
			{"an unknown puzzle mode", func(s *StationSession) { s.PuzzleMode = PuzzleMode("sometimes") }},
			{"a difficulty past the node_id", func(s *StationSession) { s.PuzzleDifficulty = 257 }},
			{"a negative difficulty", func(s *StationSession) { s.PuzzleDifficulty = -1 }},
		}
		for _, c := range cases {
			session := w.stationSession(t, challenge)
			c.change(&session)
			_, hello, err := AcceptConnect(connect, session)
			checkRefused(t, c.name, hello, err, ErrInvalidStationSession, RefusalNotAccepted)
		}
	})
}

// A HELLO refusal_code is per-hop: one this library does not know reads as
// not_accepted and is counted, and profile_unsupported is one it knows
// (macula docs/design/WIRE_1_0.md sections 3.4 and 4.4).
func TestAnUnknownRefusalCodeReadsAsNotAccepted(t *testing.T) {
	before := frame.WireCounters().EnumFallback["refusal_code"]
	_, err := ReadHello(helloRefused("quota_exceeded_v2"), Station{})
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Code != RefusalNotAccepted {
		t.Errorf("a HELLO refused with quota_exceeded_v2: %v, want a refusal read as not_accepted", err)
	}
	if got := frame.WireCounters().EnumFallback["refusal_code"]; got != before+1 {
		t.Errorf("wire_enum_fallback{refusal_code} = %d, want %d", got, before+1)
	}
	_, err = ReadHello(helloRefused(RefusalProfileUnsupported), Station{})
	if !errors.As(err, &refused) || refused.Code != RefusalProfileUnsupported {
		t.Errorf("a HELLO refused with profile_unsupported: %v, want that refusal", err)
	}
}

func isRefusal(err error, code RefusalCode) bool {
	var refused *RefusedError
	return errors.As(err, &refused) && refused.Code == code
}
