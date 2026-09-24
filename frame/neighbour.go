package frame

import (
	"bytes"
	"errors"

	"github.com/macula-io/macula-go/cbor"
	"github.com/macula-io/macula-go/identity"
	"github.com/macula-io/macula-go/profile"
)

// Neighbour signatures (D17), as macula 12's macula_frame signs and reads them.
//
// In pq_hybrid a control frame travels as {version, frame_type, neighbour}.
// neighbour is a held signed object under MACULA-PQ-NEIGHBOUR-V1, signed with
// the sender's identity key, which the receiver holds from the connection's
// handshake. Its tbs holds the frame's fields (without version), alg, the
// connection hash (the SHA-384 of the CHALLENGE frame's bytes) and seq: 0 on
// the first neighbour-signed frame in each direction, one more on each after.
// In pq_pure no frame carries one. The caller counts seq per direction and
// closes the connection on a refusal.
//
// The builders here are the control frames a client link sends in macula 12:
// ADVERTISE and UNADVERTISE carry a signed record, SUBSCRIBE and UNSUBSCRIBE a
// topic, and GOODBYE a reason.

const neighbourLabel = "MACULA-PQ-NEIGHBOUR-V1"

// The bounds macula 12's GOODBYE holds its text to; a topic's is
// maxTopicBytes (512), as for a publication.
const (
	maxGoodbyeReasonBytes = 256
	maxGoodbyeDetailBytes = 256
)

// ErrNeighbourSigned is a frame given to SignNeighbour that already carries a
// neighbour signature.
var ErrNeighbourSigned = errors.New("frame: the frame already carries a neighbour signature")

// neighbourSignedTypes are the control frames pq_hybrid neighbour-signs, as
// macula_frame's NEIGHBOUR_SIGNED lists them. Data frames carry their own
// end-to-end signatures.
var neighbourSignedTypes = map[string]bool{
	"swim_ping": true, "swim_ack": true, "swim_suspect": true, "swim_confirm": true,
	"ping": true, "pong": true, "find_node": true, "nodes": true, "find_value": true, "value": true,
	"store": true, "store_ack": true, "advertise": true, "unadvertise": true, "subscribe": true, "unsubscribe": true,
	"overlay_relay": true, "hyparview_join": true, "hyparview_forward_join": true, "hyparview_neighbor": true,
	"hyparview_disconnect": true, "hyparview_shuffle": true, "hyparview_shuffle_reply": true,
	"plumtree_ihave": true, "plumtree_graft": true, "plumtree_prune": true, "goodbye": true,
}

// NeighbourSigned reports whether profile p neighbour-signs frames of
// frameType: every control frame in pq_hybrid, none in pq_pure.
func NeighbourSigned(p profile.Profile, frameType string) bool {
	return p == profile.PQHybrid && neighbourSignedTypes[frameType]
}

// NeighbourLink is where a sender neighbour-signs a frame: the connection hash
// and the seq of this frame in the sender's direction.
type NeighbourLink struct {
	Connection [48]byte
	Seq        uint64
}

// NeighbourPeer is what a receiver checks a frame against: the connection's
// profile, the peer's identity key as carried (from the handshake), the
// connection hash, and the seq it expects next from that peer.
type NeighbourPeer struct {
	Profile    profile.Profile
	PeerKey    []byte
	Connection [48]byte
	Seq        uint64
}

// SignNeighbour neighbour-signs frame with the sender's identity key, for one
// connection and one seq, when key's profile signs its type; otherwise frame
// goes as it is. A frame that already carries a neighbour signature is refused
// with ErrNeighbourSigned.
func SignNeighbour(frame cbor.Value, key *identity.NodeKey, link NeighbourLink) (cbor.Value, error) {
	entries, isMap := frame.AsMap()
	if !isMap {
		return cbor.Value{}, ErrMalformedFrame
	}
	frameType, version, hasNeighbour := controlHeader(entries)
	switch {
	case hasNeighbour:
		return cbor.Value{}, ErrNeighbourSigned
	case !NeighbourSigned(key.Profile(), frameType):
		return frame, nil
	}
	fields := make([]cbor.MapEntry, 0, len(entries)+2)
	for _, e := range entries {
		if name, _ := e.Key.AsText(); name != "version" {
			fields = append(fields, e)
		}
	}
	fields = append(fields, bytesEntry("connection", link.Connection[:]), uintEntry("seq", link.Seq))
	held, err := identity.SignHeldObject(neighbourLabel, fields, key)
	if err != nil {
		return cbor.Value{}, err
	}
	return cbor.Map([]cbor.MapEntry{
		valueEntry("version", version),
		textEntry("frame_type", frameType),
		valueEntry("neighbour", held.Value()),
	}), nil
}

// VerifyNeighbour reads a received frame under the connection's profile. A
// frame type the profile signs must be exactly {version, frame_type,
// neighbour}, signed by the peer's identity key for this connection and this
// seq, and comes back as the frame its tbs holds. Any other frame must not
// carry neighbour and comes back as it is. A signature that does not verify is
// identity.ErrObjectSignatureInvalid; everything else refused is
// ErrMalformedFrame.
func VerifyNeighbour(frame cbor.Value, peer NeighbourPeer) (cbor.Value, error) {
	entries, isMap := frame.AsMap()
	if !isMap {
		return cbor.Value{}, ErrMalformedFrame
	}
	frameType, version, hasNeighbour := controlHeader(entries)
	if !NeighbourSigned(peer.Profile, frameType) {
		if hasNeighbour {
			return cbor.Value{}, ErrMalformedFrame
		}
		return frame, nil
	}
	if len(entries) != 3 || !hasNeighbour {
		return cbor.Value{}, ErrMalformedFrame
	}
	verified, err := identity.VerifyHeldObject(neighbourLabel, fieldOf(entries, "neighbour"), peer.PeerKey, peer.Profile)
	if err != nil {
		return cbor.Value{}, objectRefusal(err)
	}
	return openedControlFrame(verified.Fields, frameType, version, peer)
}

// openedControlFrame is the frame a neighbour tbs holds: read under its type's
// table with alg, connection and seq, which must name this connection and this
// seq, and returned without them and with version back.
func openedControlFrame(tbs cbor.Value, frameType string, version cbor.Value, peer NeighbourPeer) (cbor.Value, error) {
	table, known := controlTable(frameType)
	if !known {
		return cbor.Value{}, ErrMalformedFrame
	}
	table["alg"], table["connection"], table["seq"] = anyValue, bytesOf(48), protocolUint
	fields, ok := readFields(tbs, table)
	if !ok || !hasFields(fields, "frame_type", "alg", "connection", "seq") {
		return cbor.Value{}, ErrMalformedFrame
	}
	connection, _ := fields["connection"].AsBytes()
	seq, _ := fields["seq"].AsInt64()
	if textOf(fields["frame_type"]) != frameType || !bytes.Equal(connection, peer.Connection[:]) || uint64(seq) != peer.Seq {
		return cbor.Value{}, ErrMalformedFrame
	}
	opened := []cbor.MapEntry{valueEntry("version", version)}
	entries, _ := tbs.AsMap()
	for _, e := range entries {
		switch name, _ := e.Key.AsText(); name {
		case "alg", "connection", "seq":
		default:
			opened = append(opened, e)
		}
	}
	return cbor.Map(opened), nil
}

// controlTable is the field table of a control frame a client link exchanges,
// without version and neighbour, as macula_frame's field_table has it: the
// base every frame carries and the type's own fields.
func controlTable(frameType string) (map[string]fieldRule, bool) {
	table := map[string]fieldRule{
		"frame_type":   textIn(frameType),
		"frame_id":     anyValue,
		"sent_at_ms":   protocolUint,
		"capabilities": protocolUint,
		"realm":        anyValue,
		"call_id":      anyValue,
		"source_route": anyValue,
	}
	switch frameType {
	case "advertise":
		table["advertisement"] = anyBytes
	case "unadvertise":
		table["withdrawal"] = anyBytes
	case "subscribe":
		table["topic"], table["subscriber"], table["options"] = anyValue, bytesOf(32), anyValue
	case "unsubscribe":
		table["topic"], table["subscriber"] = anyValue, bytesOf(32)
	case "goodbye":
		table["reason"], table["detail"] = textWithin(maxGoodbyeReasonBytes), anyValue
	default:
		return nil, false
	}
	return table, true
}

// controlHeader is a frame map's frame_type, version, and whether it carries
// neighbour.
func controlHeader(entries []cbor.MapEntry) (frameType string, version cbor.Value, hasNeighbour bool) {
	version = cbor.Int(ProtocolVersion)
	for _, e := range entries {
		switch name, _ := e.Key.AsText(); name {
		case "frame_type":
			frameType, _ = e.Val.AsText()
		case "version":
			version = e.Val
		case "neighbour":
			hasNeighbour = true
		}
	}
	return frameType, version, hasNeighbour
}

func fieldOf(entries []cbor.MapEntry, name string) cbor.Value {
	for _, e := range entries {
		if key, _ := e.Key.AsText(); key == name {
			return e.Val
		}
	}
	return cbor.Null()
}

// AdvertiseFrame is macula 12's ADVERTISE: the signed procedure_advertisement
// record, as encoded bytes.
func AdvertiseFrame(advertisement []byte) cbor.Value {
	return cbor.Map(append(base("advertise", 0, freshFrameID(), currentMillis()),
		bytesEntry("advertisement", advertisement)))
}

// UnadvertiseFrame is macula 12's UNADVERTISE: the signed withdrawal record, as
// encoded bytes.
func UnadvertiseFrame(withdrawal []byte) cbor.Value {
	return cbor.Map(append(base("unadvertise", 0, freshFrameID(), currentMillis()),
		bytesEntry("withdrawal", withdrawal)))
}

// SubscribeFrame is macula 12's SUBSCRIBE of subscriber to topic in realm, with
// no options. A topic over 512 bytes or not UTF-8 is refused.
func SubscribeFrame(topic []byte, realm, subscriber [32]byte) (cbor.Value, error) {
	fields, err := topicFrame("subscribe", topic, realm, subscriber)
	if err != nil {
		return cbor.Value{}, err
	}
	return cbor.Map(append(fields, valueEntry("options", cbor.Map(nil)))), nil
}

// UnsubscribeFrame is macula 12's UNSUBSCRIBE of subscriber from topic in
// realm, with SubscribeFrame's bound on the topic.
func UnsubscribeFrame(topic []byte, realm, subscriber [32]byte) (cbor.Value, error) {
	fields, err := topicFrame("unsubscribe", topic, realm, subscriber)
	if err != nil {
		return cbor.Value{}, err
	}
	return cbor.Map(fields), nil
}

// topicFrame is the base of a SUBSCRIBE or UNSUBSCRIBE with its realm, topic
// (bytes on the wire, as macula sends it) and subscriber.
func topicFrame(frameType string, topic []byte, realm, subscriber [32]byte) ([]cbor.MapEntry, error) {
	if err := boundedText("topic", string(topic), maxTopicBytes); err != nil {
		return nil, err
	}
	fields := withField(base(frameType, 0, freshFrameID(), currentMillis()), "realm", cbor.Bytes(realm[:]))
	return append(fields, bytesEntry("topic", topic), bytesEntry("subscriber", subscriber[:])), nil
}

// GoodbyeFrame is macula 12's GOODBYE: a reason of at most 256 bytes, and a
// detail of at most 256 bytes of UTF-8, or none when detail is nil.
func GoodbyeFrame(reason string, detail []byte) (cbor.Value, error) {
	if err := boundedText("reason", reason, maxGoodbyeReasonBytes); err != nil {
		return cbor.Value{}, err
	}
	detailValue := cbor.Null()
	if detail != nil {
		if err := boundedText("detail", string(detail), maxGoodbyeDetailBytes); err != nil {
			return cbor.Value{}, err
		}
		detailValue = cbor.Bytes(detail)
	}
	return cbor.Map(append(base("goodbye", 0, freshFrameID(), currentMillis()),
		textEntry("reason", reason), valueEntry("detail", detailValue))), nil
}
