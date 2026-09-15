package handshake

import (
	"bytes"
	"crypto/sha512"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const (
	now                 = int64(1789000000000)
	minute              = int64(60000)
	hour                = 60 * minute
	day                 = 24 * hour
	stationCapabilities = uint64(5)
	clientCapabilities  = uint64(3)
	proofLabel          = "MACULA-PQ-CONNECT-PROOF-V1"
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
	}
}

func (w *world) stationSession(challenge []byte) StationSession {
	return StationSession{
		Profile:          w.profile,
		Challenge:        challenge,
		Leaf:             leaf,
		PuzzleDifficulty: 0,
		PuzzleMode:       PuzzleModeEnforce,
		Capabilities:     stationCapabilities,
		NowMs:            now + minute,
	}
}

func (w *world) challenge(t *testing.T) []byte {
	t.Helper()
	challenge, err := Challenge(w.stationMaterial())
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
	_, helloErr := ReadHello(hello)
	var refused *RefusedError
	if !errors.As(helloErr, &refused) || refused.Code != code {
		t.Errorf("%s: the HELLO reads as %v, want a refusal with %s", name, helloErr, code)
	}
}

func TestAWholeHandshakeConnectsBothSides(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		if err := ReadOpener(Opener()); err != nil {
			t.Errorf("ReadOpener(Opener()): %v", err)
		}
		challenge := w.challenge(t)
		connect, station, err := AnswerChallenge(challenge, w.clientSession())
		if err != nil {
			t.Fatalf("AnswerChallenge: %v", err)
		}
		client, hello, err := AcceptConnect(connect, w.stationSession(challenge))
		if err != nil {
			t.Fatalf("AcceptConnect: %v", err)
		}
		if station.NodeID != identity.NodeIDOf(w.station.PublicKey(), w.profile) ||
			!bytes.Equal(station.IdentityKey, w.station.PublicKey()) ||
			station.StatusExpiresAt != now+hour || station.BindingNotAfter != now+7*day {
			t.Errorf("the station as the client sees it: node_id %x, status until %d, binding until %d",
				station.NodeID, station.StatusExpiresAt, station.BindingNotAfter)
		}
		if client.NodeID != identity.NodeIDOf(w.client.PublicKey(), w.profile) ||
			!bytes.Equal(client.IdentityKey, w.client.PublicKey()) || !bytes.Equal(client.ConnectKey, w.connect.PublicKey()) ||
			client.Capabilities != clientCapabilities || client.StatusExpiresAt != now+hour ||
			client.BindingNotAfter != now+day || client.Puzzle != PuzzleResultSolved {
			t.Errorf("the client as the station sees it: node_id %x, capabilities %d, status until %d, binding until %d, puzzle %s",
				client.NodeID, client.Capabilities, client.StatusExpiresAt, client.BindingNotAfter, client.Puzzle)
		}
		if capabilities, err := ReadHello(hello); err != nil || capabilities != stationCapabilities {
			t.Errorf("ReadHello = (%d, %v), want the station's capabilities", capabilities, err)
		}
		if keys := frameKeys(t, connect); keys != "capabilities connect_binding connect_key connect_status frame_type identity_key proof version" {
			t.Errorf("CONNECT holds %q", keys)
		}
		if bytes.Equal(challenge, w.challenge(t)) {
			t.Error("two challenges are equal, want a fresh nonce in each")
		}
	})
}

// The proof signs label || 0x00 || nonce || station node_id || client node_id
// || SHA-384(leaf) || SHA-384(challenge), with the CONNECT key.
func TestTheProofSignsTheNonceBothNodeIDsTheLeafAndTheChallenge(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect := w.connectFor(t, challenge)
		nonce, _ := fields(t, challenge)["nonce"].AsBytes()
		proof, _ := fields(t, connect)["proof"].AsBytes()
		stationID := identity.NodeIDOf(w.station.PublicKey(), w.profile)
		clientID := identity.NodeIDOf(w.client.PublicKey(), w.profile)
		leafHash, challengeHash := sha512.Sum384(leaf), sha512.Sum384(challenge)
		message := concat([]byte(proofLabel), []byte{0}, nonce, stationID[:], clientID[:], leafHash[:], challengeHash[:])
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
		}
		for _, c := range cases {
			if err := answer(c.change); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
		if _, _, err := AnswerChallenge(Opener(), w.clientSession()); !errors.Is(err, ErrUnexpectedFrame) {
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
			{"a 31-byte nonce", rebuilt(t, challenge, map[string]cbor.Value{"nonce": cbor.Bytes(make([]byte, 31))}), ErrMalformedFrame},
			{"the profile as bytes", rebuilt(t, challenge, map[string]cbor.Value{"profile": cbor.Bytes([]byte(w.profile))}), ErrMalformedFrame},
			{"a TLS binding without its signature", rebuilt(t, challenge, map[string]cbor.Value{
				"tls_binding": cbor.Map([]cbor.MapEntry{{Key: cbor.Text("tbs"), Val: cbor.Bytes(nil)}}),
			}), ErrMalformedFrame},
			{"a station key one byte short", rebuilt(t, challenge, map[string]cbor.Value{"identity_key": cbor.Bytes(stationKey[:len(stationKey)-1])}), ErrMalformedFrame},
			{"version 2", rebuilt(t, challenge, map[string]cbor.Value{"version": cbor.Int(2)}), ErrUnsupportedVersion},
			{"the other profile", rebuilt(t, challenge, map[string]cbor.Value{"profile": cbor.Text(string(otherProfile(w.profile)))}), ErrProfileMismatch},
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
			{"the station's key as the CONNECT key", withConnectKey(stationKey), nil, identity.ErrBindingKeyMismatch, RefusalNotAccepted},
			{"the identity key as the CONNECT key", withConnectKey(clientKey), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
			{"the CONNECT key in the presented leaf", connect, func(s *StationSession) { s.Leaf = leafWith(connectKey) }, ErrKeyPurposeReuse, RefusalNotAccepted},
			{"a CONNECT key one byte from the identity key", withConnectKey(nearCopy(clientKey, connectKey)), nil, identity.ErrBindingKeyMismatch, RefusalNotAccepted},
			{"two hours on", connect, func(s *StationSession) { s.NowMs = now + 2*hour }, identity.ErrStatusExpired, RefusalNotAccepted},
			{"an opener", Opener(), nil, ErrUnexpectedFrame, RefusalNotAccepted},
			{"version 2", rebuilt(t, connect, map[string]cbor.Value{"version": cbor.Int(2)}), nil, ErrUnsupportedVersion, RefusalUnsupportedVersion},
			{"bytes that are not CBOR", []byte("not cbor"), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"an 8-byte proof", rebuilt(t, connect, map[string]cbor.Value{"proof": cbor.Bytes(make([]byte, 8))}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"an identity key one byte short", rebuilt(t, connect, map[string]cbor.Value{"identity_key": cbor.Bytes(clientKey[:len(clientKey)-1])}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"a CONNECT key one byte short", withConnectKey(connectKey[:len(connectKey)-1]), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"capabilities at 2^53", rebuilt(t, connect, map[string]cbor.Value{"capabilities": cbor.Int(1 << 53)}), nil, ErrMalformedFrame, RefusalNotAccepted},
			{"a proof of the right length that does not verify", rebuilt(t, connect, map[string]cbor.Value{"proof": cbor.Bytes(make([]byte, identity.SignatureSize(w.profile)))}), nil, ErrProofInvalid, RefusalNotAccepted},
			{"a CONNECT status issued 6 minutes ahead of the station", rebuilt(t, connect, map[string]cbor.Value{"connect_status": aheadOfStation.Value()}), nil, identity.ErrStatusFutureDated, RefusalNotAccepted},
		}
		if w.profile == profile.PQHybrid {
			cases = append(cases,
				refusal{"a CONNECT key sharing the identity key's RSA half", withConnectKey(concat(connectKey[:2592], clientKey[2592:])), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
				refusal{"a CONNECT key sharing the identity key's ML-DSA half", withConnectKey(concat(clientKey[:2592], connectKey[2592:])), nil, ErrKeyPurposeReuse, RefusalNotAccepted},
			)
		}
		for _, c := range cases {
			session := w.stationSession(challenge)
			if c.change != nil {
				c.change(&session)
			}
			_, hello, err := AcceptConnect(c.frame, session)
			checkRefused(t, c.name, hello, err, c.want, c.code)
		}
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
			session := w.stationSession(challenge)
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
		unsolvedSession := w.stationSession(challenge)
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

func TestAClientReadsHelloExactly(t *testing.T) {
	hello := func(changes map[string]cbor.Value) []byte {
		f := map[string]cbor.Value{"version": cbor.Int(3), "frame_type": cbor.Text("hello"), "capabilities": cbor.Int(7)}
		for key, v := range changes {
			f[key] = v
		}
		return encodeFields(f)
	}
	refusing := func(code string) map[string]cbor.Value {
		return map[string]cbor.Value{"accepted": cbor.Int(0), "refusal_code": cbor.Text(code)}
	}

	if capabilities, err := ReadHello(hello(map[string]cbor.Value{"accepted": cbor.Int(1)})); err != nil || capabilities != 7 {
		t.Errorf("an accepting HELLO: (%d, %v), want capabilities 7", capabilities, err)
	}
	_, err := ReadHello(hello(refusing("puzzle_invalid")))
	var refused *RefusedError
	if !errors.As(err, &refused) || !errors.Is(err, ErrRefused) || refused.Code != RefusalPuzzleInvalid {
		t.Errorf("a refusing HELLO: %v, want a refusal with puzzle_invalid", err)
	}
	if capabilities, err := ReadHello(hello(map[string]cbor.Value{"accepted": cbor.Int(1), "capabilities": cbor.Int(1<<53 - 1)})); err != nil || capabilities != 1<<53-1 {
		t.Errorf("capabilities 2^53-1: (%d, %v), want them read", capabilities, err)
	}
	acceptedWithCode := refusing("not_accepted")
	acceptedWithCode["accepted"] = cbor.Int(1)
	cases := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"a refusal code HELLO never sends", hello(refusing("proof_invalid")), ErrMalformedFrame},
		{"a refusal without a code", hello(map[string]cbor.Value{"accepted": cbor.Int(0)}), ErrMalformedFrame},
		{"an acceptance with a refusal code", hello(acceptedWithCode), ErrMalformedFrame},
		{"accepted 2", hello(map[string]cbor.Value{"accepted": cbor.Int(2)}), ErrMalformedFrame},
		{"capabilities at 2^53", hello(map[string]cbor.Value{"accepted": cbor.Int(1), "capabilities": cbor.Int(1 << 53)}), ErrMalformedFrame},
		{"an opener", Opener(), ErrUnexpectedFrame},
	}
	for _, c := range cases {
		if _, err := ReadHello(c.frame); !errors.Is(err, c.want) {
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
		if _, err := ReadStatus(Opener(), peer); !errors.Is(err, ErrUnexpectedFrame) {
			t.Errorf("an opener in place of a status frame: %v, want ErrUnexpectedFrame", err)
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
			session := w.stationSession(challenge)
			c.change(&session)
			_, hello, err := AcceptConnect(connect, session)
			checkRefused(t, c.name, hello, err, ErrInvalidStationSession, RefusalNotAccepted)
		}
	})
}
