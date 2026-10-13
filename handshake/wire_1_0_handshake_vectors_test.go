package handshake

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/internal/wire10vectors"
	"github.com/macula-io/macula-go/profile"
)

// The wire 1.0 handshake vectors (macula priv/vectors/wire_1_0/handshake.json,
// macula#98): opener-to-HELLO transcripts, replayed step by step. Each frame
// the client sent gets the verdict this library's station side reaches on it,
// and each frame the station sent the verdict its client side reaches, under
// the fixed public keys, so nothing is signed: a station's session proof is
// stood in for, and the proof and session proof messages are compared byte for
// byte with the transcript's.

// handshakeRefusals are the close reasons by name.
var handshakeRefusals = map[string]error{
	"malformed_frame":       ErrMalformedFrame,
	"unsupported_version":   ErrUnsupportedVersion,
	"profile_unsupported":   ErrProfileUnsupported,
	"negotiation_mismatch":  ErrNegotiationMismatch,
	"downgrade_detected":    ErrDowngradeDetected,
	"version_below_floor":   ErrVersionBelowFloor,
	"proof_invalid":         ErrProofInvalid,
	"puzzle_invalid":        ErrPuzzleInvalid,
	"session_proof_invalid": ErrSessionProofInvalid,
	"session_proof_missing": ErrSessionProofMissing,
}

// vectorSide is one end's input: its ranges, capabilities and floor.
type vectorSide struct {
	ranges       Ranges
	capabilities uint64
	floor        Floor
	expected     [32]byte
	puzzle       struct {
		difficulty int
		mode       PuzzleMode
	}
}

func sideOf(t *testing.T, raw any) vectorSide {
	t.Helper()
	m, _ := raw.(map[string]any)
	var s vectorSide
	versions, _ := m["versions"].([]any)
	if len(versions) == 2 {
		s.ranges.MinVersion, s.ranges.MaxVersion = int64(versions[0].(float64)), int64(versions[1].(float64))
	}
	profiles, _ := m["profiles"].([]any)
	for _, p := range profiles {
		s.ranges.Profiles = append(s.ranges.Profiles, profile.Profile(p.(string)))
	}
	capabilities, _ := m["capabilities"].(float64)
	s.capabilities = uint64(capabilities)
	floors := map[[32]byte]int64{}
	entries, _ := m["floor"].([]any)
	for _, e := range entries {
		fl := e.(map[string]any)
		floors[mustHex32(t, fl["node_id"].(string))] = int64(fl["version"].(float64))
	}
	s.floor = func(nodeID [32]byte) int64 { return floors[nodeID] }
	if expected, ok := m["expected_station_node_id"].(string); ok {
		s.expected = mustHex32(t, expected)
	}
	if puzzle, ok := m["puzzle"].(map[string]any); ok {
		s.puzzle.difficulty = int(puzzle["difficulty"].(float64))
		s.puzzle.mode = PuzzleMode(puzzle["mode"].(string))
	}
	return s
}

func mustHex32(t *testing.T, s string) (out [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("a 32-byte id: %q", s)
	}
	copy(out[:], b)
	return out
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// wantVerdict checks one step's error against its expect.
func wantVerdict(t *testing.T, step int, err error, expect map[string]any) {
	t.Helper()
	outcome, _ := expect["outcome"].(string)
	reason, _ := expect["reason"].(string)
	switch {
	case outcome == "accept" && err != nil:
		t.Fatalf("step %d: %v, want it accepted", step, err)
	case outcome == "accept":
		return
	case len(reason) > len("refused:") && reason[:len("refused:")] == "refused:":
		var refused *RefusedError
		if !errors.As(err, &refused) || string(refused.Code) != reason[len("refused:"):] {
			t.Fatalf("step %d: %v, want a HELLO refusal %s", step, err, reason)
		}
	default:
		want, known := handshakeRefusals[reason]
		if !known {
			t.Fatalf("step %d: no error carries %s", step, reason)
		}
		if !errors.Is(err, want) {
			t.Fatalf("step %d: %v, want %s", step, err, reason)
		}
	}
}

// wantHello checks a station's refusing HELLO: its wire refusal code, and for
// an early refusal the ranges it names.
func wantHello(t *testing.T, step int, hello []byte, expect map[string]any) {
	t.Helper()
	code, _ := expect["wire_refusal"].(string)
	if code == "" {
		return
	}
	_, err := ReadHello(hello, Station{})
	var refused *RefusedError
	if !errors.As(err, &refused) || string(refused.Code) != code {
		t.Fatalf("step %d: the HELLO sent reads %v, want refusal_code %s", step, err, code)
	}
	if want, ok := expect["hello"].(map[string]any); ok {
		named := sideOf(t, want).ranges
		if refused.StationRanges == nil || !sameRanges(*refused.StationRanges, named) {
			t.Fatalf("step %d: the HELLO names %+v, want %+v", step, refused.StationRanges, named)
		}
	}
}

func TestTheWireOneHandshakeVectors(t *testing.T) {
	f, err := wire10vectors.Load("handshake")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := wire10vectors.LoadKeys()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		t.Run(c.ID, func(t *testing.T) {
			p := profile.Profile(c.Profile)
			client, station := sideOf(t, c.Input["client"]), sideOf(t, c.Input["station"])
			tls, _ := c.Input["tls"].(map[string]any)
			leaf, e := mustHex(t, tls["leaf_der"].(string)), mustHex(t, tls["exporter"].(string))
			export := func(string, []byte, int) ([]byte, error) { return e, nil }
			now := c.Int("now_ms")
			clientIdentity, err := keys.Key(c.Profile, "client_identity")
			if err != nil {
				t.Fatal(err)
			}
			var (
				negotiated Negotiated
				challenge  []byte
				connect    []byte
				read       Station
				captured   []byte
			)
			steps, _ := c.Input["steps"].([]any)
			for i, raw := range steps {
				step := raw.(map[string]any)
				frameBytes := mustHex(t, step["frame"].(string))
				expect, _ := step["expect"].(map[string]any)
				switch from := step["from"].(string); {
				case from == "client" && i == 0:
					n, hello, err := ReadOpener(frameBytes, station.ranges)
					wantVerdict(t, i, err, expect)
					wantHello(t, i, hello, expect)
					negotiated = n
				case from == "station" && challenge == nil && frameTypeOf(t, frameBytes) == "challenge":
					challenge = frameBytes
					s, err := ReadChallenge(frameBytes, ClientSession{
						Profile: p, ExpectedNodeID: client.expected, Leaf: leaf, IdentityKey: clientIdentity,
						NowMs: now, Ranges: client.ranges, Floor: client.floor, Export: export,
						connectPublic: connectKeyOf(t, steps, keys, c.Profile),
					})
					wantVerdict(t, i, err, expect)
					read = s
				case from == "client":
					connect = frameBytes
					_, hello, err := AcceptConnect(frameBytes, StationSession{
						Profile: p, Negotiated: negotiated, Challenge: challenge, Leaf: leaf,
						PuzzleDifficulty: station.puzzle.difficulty, PuzzleMode: station.puzzle.mode,
						Capabilities: station.capabilities, NowMs: now, Floor: station.floor, Export: export,
						SignSessionProof: func(_ [32]byte, message []byte) ([]byte, error) {
							captured = message
							return make([]byte, identity.SignatureSize(p)), nil
						},
					})
					wantVerdict(t, i, err, expect)
					wantHello(t, i, hello, expect)
					if want, ok := step["proof_message"].(string); ok {
						tbs, err := connectTBS(frameBytes)
						if err != nil {
							t.Fatalf("step %d: the CONNECT tbs: %v", i, err)
						}
						if got := read.proofMessage(tbs); !bytes.Equal(got, mustHex(t, want)) {
							t.Errorf("step %d: proof message\n got %x\nwant %s", i, got, want)
						}
					}
				default:
					read.connect = connect
					_, err := ReadHello(frameBytes, read)
					wantVerdict(t, i, err, expect)
					wantStationRanges(t, i, err, expect)
					if want, ok := step["session_proof_message"].(string); ok && !bytes.Equal(captured, mustHex(t, want)) {
						t.Errorf("step %d: session proof message\n got %x\nwant %s", i, captured, want)
					}
				}
			}
		})
	}
}

// frameTypeOf is a transcript frame's frame_type.
func frameTypeOf(t *testing.T, frame []byte) string {
	t.Helper()
	v, err := cbor.Decode(frame)
	if err != nil {
		t.Fatalf("a transcript frame does not decode: %v", err)
	}
	frameType, _ := v.Get("frame_type")
	text, _ := frameType.AsText()
	return text
}

// wantStationRanges checks the ranges an early refusal names against the
// step's station_ranges, when it has them.
func wantStationRanges(t *testing.T, step int, err error, expect map[string]any) {
	t.Helper()
	want, has := expect["station_ranges"].(map[string]any)
	if !has {
		return
	}
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.StationRanges == nil {
		t.Fatalf("step %d: %v, want a refusal naming the station's ranges", step, err)
	}
	if got := refused.StationRanges; !sameRanges(*got, sideOf(t, want).ranges) {
		t.Errorf("step %d: the station's ranges %+v, want %v", step, *got, want)
	}
}

// connectKeyOf is the CONNECT key the transcript's client carries, from its
// CONNECT, or the vectors' fixed CONNECT key when it sends none.
func connectKeyOf(t *testing.T, steps []any, keys wire10vectors.Keys, p string) []byte {
	t.Helper()
	for _, raw := range steps {
		step := raw.(map[string]any)
		if f, err := decode(mustHex(t, step["frame"].(string)), "connect", connectKeys); err == nil {
			return f.bytes("connect_key")
		}
	}
	key, err := keys.Key(p, "client_connect")
	if err != nil {
		t.Fatal(err)
	}
	return key
}
