// Command gohandshake is macula-go's step of the cross-stack handshake check:
// it answers each CHALLENGE macula's macula_handshake made, and makes a
// CHALLENGE of its own for macula to answer. See
// scripts/interop/erlang_handshake.escript and scripts/interop/run.sh.
//
//	go run ./scripts/interop/gohandshake <erlang_challenges.json> <go_handshake.json>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/macula-io/macula-go/handshake"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

const (
	minuteMs     = int64(60 * 1000)
	hourMs       = 60 * minuteMs
	dayMs        = 24 * hourMs
	capabilities = 3
)

type erlangChallenge struct {
	Profile       string `json:"profile"`
	Now           int64  `json:"now"`
	Leaf          string `json:"leaf"`
	Challenge     string `json:"challenge"`
	StationNodeID string `json:"station_node_id"`
}

type goEntry struct {
	Profile       string `json:"profile"`
	Connect       string `json:"connect"`
	Challenge     string `json:"challenge"`
	StationNodeID string `json:"station_node_id"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gohandshake <erlang_challenges.json> <go_handshake.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "gohandshake:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var challenges struct {
		Entries []erlangChallenge `json:"entries"`
	}
	if err := json.Unmarshal(raw, &challenges); err != nil {
		return err
	}
	entries := make([]goEntry, 0, len(challenges.Entries))
	for _, c := range challenges.Entries {
		entry, err := both(c)
		if err != nil {
			return fmt.Errorf("%s: %w", c.Profile, err)
		}
		entries = append(entries, entry)
	}
	encoded, err := json.MarshalIndent(map[string]any{"entries": entries}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Printf("gohandshake: answered %d macula CHALLENGEs and made %d of its own\n", len(entries), len(entries))
	return os.WriteFile(out, encoded, 0o644)
}

func both(c erlangChallenge) (goEntry, error) {
	p, err := profile.Parse(c.Profile)
	if err != nil {
		return goEntry{}, err
	}
	leaf, challenge, stationNodeID, err := decoded(c)
	if err != nil {
		return goEntry{}, err
	}
	connect, err := answer(p, leaf, challenge, stationNodeID, c.Now)
	if err != nil {
		return goEntry{}, fmt.Errorf("answer macula's CHALLENGE: %w", err)
	}
	ownChallenge, ownNodeID, err := station(p, leaf, c.Now)
	if err != nil {
		return goEntry{}, fmt.Errorf("make a CHALLENGE: %w", err)
	}
	return goEntry{Profile: c.Profile, Connect: hex.EncodeToString(connect),
		Challenge: hex.EncodeToString(ownChallenge), StationNodeID: hex.EncodeToString(ownNodeID[:])}, nil
}

func decoded(c erlangChallenge) (leaf, challenge []byte, stationNodeID [32]byte, err error) {
	if leaf, err = hex.DecodeString(c.Leaf); err != nil {
		return
	}
	if challenge, err = hex.DecodeString(c.Challenge); err != nil {
		return
	}
	id, err := hex.DecodeString(c.StationNodeID)
	if err == nil && len(id) != 32 {
		err = fmt.Errorf("station node_id is %d bytes", len(id))
	}
	copy(stationNodeID[:], id)
	return
}

// answer is macula-go's CONNECT to a macula CHALLENGE, from a fresh client.
func answer(p profile.Profile, leaf, challenge []byte, stationNodeID [32]byte, now int64) ([]byte, error) {
	client, err := identity.GenerateIdentityKey(p, 0)
	if err != nil {
		return nil, err
	}
	connectKey, err := identity.GenerateKey(identity.PurposeConnect, p)
	if err != nil {
		return nil, err
	}
	binding, err := identity.ConnectBinding(client, connectKey.PublicKey(), now, now+dayMs)
	if err != nil {
		return nil, err
	}
	status, err := identity.StatusStatement(client, binding, now, now+hourMs)
	if err != nil {
		return nil, err
	}
	connect, _, err := handshake.AnswerChallenge(challenge, handshake.ClientSession{
		Profile: p, ExpectedNodeID: stationNodeID, Leaf: leaf, IdentityKey: client.PublicKey(),
		ConnectKey: connectKey, ConnectBinding: binding, ConnectStatus: status,
		Capabilities: capabilities, NowMs: now + minuteMs,
	})
	return connect, err
}

// station is a fresh macula-go station's CHALLENGE over leaf, and its node_id.
func station(p profile.Profile, leaf []byte, now int64) ([]byte, [32]byte, error) {
	key, err := identity.GenerateIdentityKey(p, 0)
	if err != nil {
		return nil, [32]byte{}, err
	}
	binding, err := identity.TLSBinding(key, leaf, now, now+7*dayMs)
	if err != nil {
		return nil, [32]byte{}, err
	}
	status, err := identity.StatusStatement(key, binding, now, now+hourMs)
	if err != nil {
		return nil, [32]byte{}, err
	}
	challenge, err := handshake.Challenge(handshake.StationMaterial{
		Profile: p, IdentityKey: key.PublicKey(), TLSBinding: binding, TLSStatus: status,
	})
	if err != nil {
		return nil, [32]byte{}, err
	}
	nodeID, err := key.NodeID()
	return challenge, nodeID, err
}
