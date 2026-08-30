package frame

import "github.com/macula-io/macula-go/cbor"

// ConnectSpec holds the fields for a CONNECT frame — see
// plans/PLAN_WIRE_PROTOCOL.md §5.
type ConnectSpec struct {
	NodeID         []byte   // 32 bytes, Ed25519 pubkey
	StationID      []byte   // 32 bytes
	Realms         [][]byte // each 32 bytes
	Capabilities   uint64
	PuzzleEvidence []byte // 32 bytes, SHA-256(NodeID)
	Addresses      []cbor.Value
	Site           *cbor.Value
	Endorsements   []cbor.Value
}

// NewConnectSpec builds a CONNECT with no realm memberships claimed and
// no advertised addresses — the shape a dial-out-only leaf client uses.
func NewConnectSpec(nodeID, puzzleEvidence []byte) ConnectSpec {
	return ConnectSpec{
		NodeID: nodeID,
		// send_connect/2's own convention: a plain peer/daemon dial sets
		// station_id equal to node_id.
		StationID:      nodeID,
		Capabilities:   0,
		PuzzleEvidence: puzzleEvidence,
	}
}

func connectValue(spec ConnectSpec, frameID []byte, sentAtMs int64) cbor.Value {
	fields := base("connect", spec.Capabilities, frameID, sentAtMs)
	fields = append(fields,
		cbor.MapEntry{Key: cbor.Text("node_id"), Val: cbor.Bytes(spec.NodeID)},
		cbor.MapEntry{Key: cbor.Text("station_id"), Val: cbor.Bytes(spec.StationID)},
		cbor.MapEntry{Key: cbor.Text("realms"), Val: bytes32List(spec.Realms)},
		cbor.MapEntry{Key: cbor.Text("addresses"), Val: cbor.List(spec.Addresses)},
	)
	site := cbor.Null()
	if spec.Site != nil {
		site = *spec.Site
	}
	fields = append(fields,
		cbor.MapEntry{Key: cbor.Text("site"), Val: site},
		cbor.MapEntry{Key: cbor.Text("puzzle_evidence"), Val: cbor.Bytes(spec.PuzzleEvidence)},
		cbor.MapEntry{Key: cbor.Text("endorsements"), Val: cbor.List(spec.Endorsements)},
	)
	return cbor.Map(fields)
}

// Connect builds a CONNECT frame with a fresh frame_id/sent_at_ms.
// Unsigned — pass the result to Sign before sending.
func Connect(spec ConnectSpec) cbor.Value {
	return connectValue(spec, freshFrameID(), currentMillis())
}
