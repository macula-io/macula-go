package handshake

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// erlangHandshake is testdata/erlang_handshake.json: frames macula 12.1.0's
// macula_handshake made (scripts/interop/erlang_handshake.escript), at
// macula's own test instant. For each profile, a CHALLENGE macula made as a
// station, and a CONNECT macula made answering a CHALLENGE macula-go made.
type erlangHandshake struct {
	Generator string `json:"generator"`
	Now       int64  `json:"now"`
	Leaf      string `json:"leaf"`
	Entries   []struct {
		Profile             string `json:"profile"`
		ErlangChallenge     string `json:"erlang_challenge"`
		ErlangStationNodeID string `json:"erlang_station_node_id"`
		GoChallenge         string `json:"go_challenge"`
		ErlangConnect       string `json:"erlang_connect"`
		GoConnectV5         string `json:"go_connect_v5"`
		ErlangHelloV5       string `json:"erlang_hello_v5"`
		ErlangConnectV5     string `json:"erlang_connect_v5"`
	} `json:"entries"`
}

func loadErlangHandshake(t *testing.T) erlangHandshake {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "erlang_handshake.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var h erlangHandshake
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if len(h.Entries) != 2 {
		t.Fatalf("fixture holds %d entries, want pq_pure and pq_hybrid", len(h.Entries))
	}
	return h
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex: %v", err)
	}
	return b
}

// A CONNECT macula made is accepted by macula-go's station check, against the
// CHALLENGE macula-go made, with an empty member_endorsement handed on.
func TestAConnectMaculaMadeIsAccepted(t *testing.T) {
	h := loadErlangHandshake(t)
	for _, e := range h.Entries {
		t.Run(e.Profile, func(t *testing.T) {
			client, hello, err := AcceptConnect(unhex(t, e.ErlangConnect), StationSession{
				Profile: profile.Profile(e.Profile), Challenge: unhex(t, e.GoChallenge), Leaf: unhex(t, h.Leaf),
				PuzzleDifficulty: 0, PuzzleMode: PuzzleModeEnforce, Capabilities: 5, NowMs: h.Now + 60_000,
			})
			if err != nil {
				t.Fatalf("AcceptConnect: %v", err)
			}
			if _, err := ReadHello(hello, Station{}); err != nil {
				t.Errorf("the HELLO: %v", err)
			}
			if client.MemberEndorsement == nil || len(client.MemberEndorsement) != 0 {
				t.Errorf("member_endorsement %x, want empty", client.MemberEndorsement)
			}
		})
	}
}

// A CHALLENGE macula made is answered by a fresh macula-go client: macula's
// bindings, status statement and node_id all check out.
func TestAChallengeMaculaMadeIsAnswered(t *testing.T) {
	h := loadErlangHandshake(t)
	for _, e := range h.Entries {
		t.Run(e.Profile, func(t *testing.T) {
			p := profile.Profile(e.Profile)
			client, err := identity.GenerateIdentityKey(p, 0)
			if err != nil {
				t.Fatalf("identity key: %v", err)
			}
			connectKey, err := identity.GenerateKey(identity.PurposeConnect, p)
			if err != nil {
				t.Fatalf("CONNECT key: %v", err)
			}
			binding, err := identity.ConnectBinding(client, connectKey.PublicKey(), h.Now, h.Now+86_400_000)
			if err != nil {
				t.Fatalf("CONNECT binding: %v", err)
			}
			status, err := identity.StatusStatement(client, binding, h.Now, h.Now+3_600_000)
			if err != nil {
				t.Fatalf("status: %v", err)
			}
			var stationNodeID [32]byte
			copy(stationNodeID[:], unhex(t, e.ErlangStationNodeID))
			connect, station, err := AnswerChallenge(unhex(t, e.ErlangChallenge), ClientSession{
				Profile: p, ExpectedNodeID: stationNodeID, Leaf: unhex(t, h.Leaf), IdentityKey: client.PublicKey(),
				ConnectKey: connectKey, ConnectBinding: binding, ConnectStatus: status, Capabilities: 3, NowMs: h.Now + 60_000,
			})
			if err != nil {
				t.Fatalf("AnswerChallenge: %v", err)
			}
			if station.NodeID != stationNodeID || len(connect) == 0 {
				t.Errorf("the station as seen: node_id %x, CONNECT %d bytes", station.NodeID, len(connect))
			}
		})
	}
}

// A v5 CONNECT macula made, answering a CHALLENGE macula-go made, is accepted by
// macula-go's station check in version 5: macula's V2 proof message, exporter
// context and capability encoding are macula-go's, byte for byte, or the proof
// would not verify.
func TestAV5ConnectMaculaMadeIsAccepted(t *testing.T) {
	h := loadErlangHandshake(t)
	for _, e := range h.Entries {
		t.Run(e.Profile, func(t *testing.T) {
			client, hello, err := AcceptConnect(unhex(t, e.ErlangConnectV5), StationSession{
				Profile: profile.Profile(e.Profile), Challenge: unhex(t, e.GoChallenge), Leaf: unhex(t, h.Leaf),
				PuzzleDifficulty: 0, PuzzleMode: PuzzleModeEnforce, Capabilities: 5, NowMs: h.Now + 60_000,
				Export:           exporterOf("session_a"),
				SignSessionProof: func(_ [32]byte, _ []byte) ([]byte, error) { return []byte("unread"), nil },
			})
			if err != nil || client.Version != 5 || len(hello) == 0 {
				t.Fatalf("AcceptConnect v5: version %d, %v", client.Version, err)
			}
		})
	}
}

// The v5 HELLO macula made for macula-go's v5 CONNECT proves the session to
// macula-go's client check: macula's session proof message is macula-go's, byte
// for byte.
func TestAV5HelloMaculaMadeProvesTheSession(t *testing.T) {
	h := loadErlangHandshake(t)
	for _, e := range h.Entries {
		t.Run(e.Profile, func(t *testing.T) {
			p := profile.Profile(e.Profile)
			challenge, connect := unhex(t, e.ErlangChallenge), unhex(t, e.GoConnectV5)
			challengeFields, err := decode(challenge, "challenge", challengeKeys)
			if err != nil {
				t.Fatalf("macula's CHALLENGE: %v", err)
			}
			connectFields, err := decodeVersioned(connect, "connect", map[int64][][]string{Version5: {connectKeys}})
			if err != nil {
				t.Fatalf("macula-go's v5 CONNECT: %v", err)
			}
			stationKey := challengeFields.bytes("identity_key")
			stationNodeID := identity.NodeIDOf(stationKey, p)
			clientNodeID := identity.NodeIDOf(connectFields.bytes("identity_key"), p)
			station := Station{NodeID: stationNodeID, IdentityKey: stationKey, Version: Version5, profile: p,
				exporterValue: exported("session_a", append(clientNodeID[:], stationNodeID[:]...)),
				challenge: challenge, connect: connect, clientNodeID: clientNodeID}
			if capabilities, err := ReadHello(unhex(t, e.ErlangHelloV5), station); err != nil || capabilities != 5 {
				t.Errorf("ReadHello of macula's v5 HELLO: (%d, %v), want the station's capabilities 5", capabilities, err)
			}
		})
	}
}
