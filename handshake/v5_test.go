package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// Handshake v5 (macula docs/design/DESIGN_NEIGHBOUR_CHANNEL_BINDING.md section 3): both proofs bound to the TLS session's
// exporter value E. These mirror macula's macula_handshake_tests v5 cases.

const (
	proofLabelV2        = "MACULA-PQ-CONNECT-PROOF-V2"
	mldsaSignatureBytes = 4627
)

// exporterOf stands in for one TLS session's exporter: the same label, context and length give the same bytes on
// both ends, and another session gives other bytes. macula's tests use the same stand-in, so frames made by one
// stack verify in the other.
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

func (w *world) clientSessionV5() ClientSession {
	s := w.clientSession()
	s.Version = Version5
	s.Export = exporterOf("session_a")
	return s
}

func (w *world) stationSessionV5(challenge []byte) StationSession {
	s := w.stationSession(challenge)
	s.Export = exporterOf("session_a")
	s.SignSessionProof = func(_ [32]byte, message []byte) ([]byte, error) { return w.station.Sign(message) }
	return s
}

// The session proof's message for this challenge and CONNECT under session's exporter, as the station signs it.
func (w *world) sessionMessage(challenge, connect []byte, session string) []byte {
	stationID := identity.NodeIDOf(w.station.PublicKey(), w.profile)
	clientID := identity.NodeIDOf(w.client.PublicKey(), w.profile)
	challengeHash, connectHash := sha512.Sum384(challenge), sha512.Sum384(connect)
	return concat([]byte("MACULA-PQ-SESSION-PROOF-V1"), []byte{0}, exported(session, concat(clientID[:], stationID[:])),
		challengeHash[:], connectHash[:], stationID[:], clientID[:], be64(stationCapabilities))
}

func be64(n uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, n)
}

func (w *world) v5Pair(t *testing.T) (challenge, connect []byte, station Station, client Client, hello []byte) {
	t.Helper()
	challenge = w.challenge(t)
	connect, station, err := AnswerChallenge(challenge, w.clientSessionV5())
	if err != nil {
		t.Fatalf("AnswerChallenge v5: %v", err)
	}
	client, hello, err = AcceptConnect(connect, w.stationSessionV5(challenge))
	if err != nil {
		t.Fatalf("AcceptConnect v5: %v", err)
	}
	return challenge, connect, station, client, hello
}

func TestAWholeV5HandshakeConnectsBothSides(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge, connect, station, client, hello := w.v5Pair(t)
		version := func(frame []byte) int64 { v, _ := fields(t, frame)["version"].AsInt64(); return v }
		if version(Opener()) != 4 || version(challenge) != 4 {
			t.Errorf("opener and challenge are versions %d and %d, want 4: the client picks the version in CONNECT",
				version(Opener()), version(challenge))
		}
		if version(connect) != 5 || version(hello) != 5 {
			t.Errorf("CONNECT and HELLO are versions %d and %d, want 5", version(connect), version(hello))
		}
		if keys := frameKeys(t, connect); keys != "capabilities connect_binding connect_key connect_status frame_type identity_key member_endorsement proof version" {
			t.Errorf("a v5 CONNECT holds %q, want v4's keys", keys)
		}
		if keys := frameKeys(t, hello); keys != "accepted capabilities frame_type session_proof version" {
			t.Errorf("a v5 HELLO holds %q", keys)
		}
		if station.Version != 5 || client.Version != 5 {
			t.Errorf("versions: station %d, client %d, want 5", station.Version, client.Version)
		}
		if capabilities, err := ReadHello(hello, station); err != nil || capabilities != stationCapabilities {
			t.Errorf("ReadHello v5 = (%d, %v), want the station's capabilities", capabilities, err)
		}
	})
}

// The V2 CONNECT proof: label || 0x00 || nonce || station node_id || client node_id || SHA-384(leaf) ||
// SHA-384(challenge) || E || client capabilities, 8 bytes big-endian. The session proof: label || 0x00 || E ||
// SHA-384(challenge) || SHA-384(CONNECT) || station node_id || client node_id || station capabilities.
func TestTheV5ProofsSignWhatTheDesignSays(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge, connect, _, _, hello := w.v5Pair(t)
		stationID := identity.NodeIDOf(w.station.PublicKey(), w.profile)
		clientID := identity.NodeIDOf(w.client.PublicKey(), w.profile)
		e := exported("session_a", concat(clientID[:], stationID[:]))
		nonce, _ := fields(t, challenge)["nonce"].AsBytes()
		leafHash, challengeHash := sha512.Sum384(leaf), sha512.Sum384(challenge)
		connectMessage := concat([]byte(proofLabelV2), []byte{0}, nonce, stationID[:], clientID[:], leafHash[:],
			challengeHash[:], e, be64(clientCapabilities))
		proof, _ := fields(t, connect)["proof"].AsBytes()
		if !identity.Verify(connectMessage, proof, w.connect.PublicKey(), w.profile) {
			t.Error("the CONNECT proof does not verify over the V2 message")
		}
		sessionProof, _ := fields(t, hello)["session_proof"].AsBytes()
		if !identity.Verify(w.sessionMessage(challenge, connect, "session_a"), sessionProof, w.station.PublicKey(), w.profile) {
			t.Error("the session proof does not verify over its message")
		}
	})
}

func TestAStationRefusesAV5ConnectItCannotTrust(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect, _, err := AnswerChallenge(challenge, w.clientSessionV5())
		if err != nil {
			t.Fatalf("AnswerChallenge v5: %v", err)
		}
		connectV4, _, err := AnswerChallenge(challenge, w.clientSession())
		if err != nil {
			t.Fatalf("AnswerChallenge v4: %v", err)
		}
		otherSession := w.stationSessionV5(challenge)
		otherSession.Export = exporterOf("session_b")
		if _, hello, err := AcceptConnect(connect, otherSession); !errors.Is(err, ErrProofInvalid) || helloVersion(t, hello) != 5 {
			t.Errorf("a proof over another session's E: %v, HELLO version %d, want ErrProofInvalid in version 5", err, helloVersion(t, hello))
		}
		relabelled := rebuilt(t, connectV4, map[string]cbor.Value{"version": cbor.Int(5)})
		if _, _, err := AcceptConnect(relabelled, w.stationSessionV5(challenge)); !errors.Is(err, ErrProofInvalid) {
			t.Errorf("a v4 CONNECT relabelled 5: %v, want ErrProofInvalid", err)
		}
		client, hello, err := AcceptConnect(connectV4, w.stationSessionV5(challenge))
		if err != nil || client.Version != 4 || helloVersion(t, hello) != 4 {
			t.Errorf("a v4 CONNECT at a station that speaks both: (%d, HELLO %d, %v), want a v4 handshake",
				client.Version, helloVersion(t, hello), err)
		}
		// A station with no exporter answers v5 as an old station does.
		_, hello, err = AcceptConnect(connect, w.stationSession(challenge))
		if !errors.Is(err, ErrUnsupportedVersion) || helloVersion(t, hello) != 4 {
			t.Errorf("v5 at a station without an exporter: %v, HELLO version %d, want unsupported_version in version 4", err, helloVersion(t, hello))
		}
		if _, readErr := ReadHello(hello, Station{Version: 5}); !isRefusal(readErr, RefusalUnsupportedVersion) {
			t.Errorf("that HELLO reads as %v, want a refusal with unsupported_version", readErr)
		}
		if _, _, err := AcceptConnect(rebuilt(t, connect, map[string]cbor.Value{"version": cbor.Int(6)}), w.stationSessionV5(challenge)); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("version 6: %v, want ErrUnsupportedVersion", err)
		}
	})
}

// Sign after verify: a CONNECT that fails any check never reaches the signer. Past the budget the station refuses
// with session_proof_rate, on the wire too.
func TestAStationSignsTheSessionProofOnlyAfterEveryCheckAndWithinItsBudget(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge := w.challenge(t)
		connect, station, err := AnswerChallenge(challenge, w.clientSessionV5())
		if err != nil {
			t.Fatalf("AnswerChallenge v5: %v", err)
		}
		signed := 0
		watched := w.stationSessionV5(challenge)
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

func TestAClientRefusesAV5HelloThatDoesNotProveTheSession(t *testing.T) {
	forEachWorld(t, func(t *testing.T, w *world) {
		challenge, connect, station, _, hello := w.v5Pair(t)
		otherKey, err := identity.GenerateKey(identity.PurposeIdentity, w.profile)
		if err != nil {
			t.Fatal(err)
		}
		overOtherE, _ := w.station.Sign(w.sessionMessage(challenge, connect, "session_b"))
		byOtherKey, _ := otherKey.Sign(w.sessionMessage(challenge, connect, "session_a"))
		_, _, _, _, otherConnection := w.v5Pair(t)
		connectV4, _, _ := AnswerChallenge(challenge, w.clientSession())
		_, helloV4, err := AcceptConnect(connectV4, w.stationSession(challenge))
		if err != nil {
			t.Fatalf("v4 pair: %v", err)
		}
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
			{"a v4 acceptance of a v5 CONNECT", helloV4, ErrV4HelloToV5Connect},
		}
		for _, c := range cases {
			if _, err := ReadHello(c.hello, station); !errors.Is(err, c.want) {
				t.Errorf("%s: %v, want %v", c.name, err, c.want)
			}
		}
		if _, err := ReadHello(hello, Station{Version: 4}); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("a v5 HELLO after a v4 CONNECT: %v, want ErrUnsupportedVersion", err)
		}
	})
}

// The case D17 existed for: an attacker who can forge ML-DSA-87 but not RSA-PSS-4096. A session proof whose ML-DSA
// half is the station's own, valid, and whose RSA half is another key's, is refused.
func TestAHybridSessionProofWithAForeignRSAHalfIsRefused(t *testing.T) {
	w, err := worlds[profile.PQHybrid]()
	if err != nil {
		t.Fatalf("world: %v", err)
	}
	challenge, connect, station, _, hello := w.v5Pair(t)
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

func helloVersion(t *testing.T, hello []byte) int64 {
	t.Helper()
	v, _ := fields(t, hello)["version"].AsInt64()
	return v
}

func isRefusal(err error, code RefusalCode) bool {
	var refused *RefusedError
	return errors.As(err, &refused) && refused.Code == code
}
