package frame

import (
	"github.com/macula-io/macula-go/cbor"
)

// The control frames a client link exchanges after HELLO (macula
// docs/design/WIRE_1_0.md section 3): ADVERTISE and UNADVERTISE carry a signed
// record, SUBSCRIBE and UNSUBSCRIBE a topic, and GOODBYE a reason. None
// carries a signature of its own: the session proofs authenticated the peer
// once, and QUIC's AEAD authenticates every frame.

// The bounds macula's GOODBYE holds its text to; a topic's is maxTopicBytes
// (512), as for a publication.
const (
	maxGoodbyeReasonBytes = 256
	maxGoodbyeDetailBytes = 256
)

// controlTable is the field table of a control frame a client link exchanges:
// the envelope every frame carries and the type's own fields, and the fields
// it must hold.
func controlTable(frameType string) (map[string]fieldRule, []string, bool) {
	table := map[string]fieldRule{
		"version":    protocolVersion,
		"frame_type": textIn(frameType),
		"frame_id":   envelopeRules["frame_id"],
		"sent_at_ms": envelopeRules["sent_at_ms"],
	}
	switch frameType {
	case "advertise":
		table["advertisement"] = anyBytes
		return table, []string{"advertisement"}, true
	case "unadvertise":
		table["withdrawal"] = anyBytes
		return table, []string{"withdrawal"}, true
	case "subscribe":
		table["realm"], table["topic"], table["subscriber"], table["options"] = bytesOf(32), anyBytes, bytesOf(32), anyMap
		return table, []string{"realm", "topic", "subscriber"}, true
	case "unsubscribe":
		table["realm"], table["topic"], table["subscriber"] = bytesOf(32), anyBytes, bytesOf(32)
		return table, []string{"realm", "topic", "subscriber"}, true
	case "goodbye":
		table["reason"], table["detail"] = textWithin(maxGoodbyeReasonBytes), bytesWithin(maxGoodbyeDetailBytes)
		return table, []string{"reason"}, true
	}
	return nil, nil, false
}

// ReadControl reads a control frame, its envelope already read (ReadEnvelope),
// through its type's table: exactly the envelope keys and the type's fields,
// each of its rule, with the fields the type requires. A frame of another type
// or shape is ErrMalformedFrame: a field no table names is an extra core
// field, so a frame that carries a neighbour signature is refused too.
func ReadControl(v cbor.Value) (cbor.Value, error) {
	frameType, _ := v.Get("frame_type")
	table, required, known := controlTable(textOf(frameType))
	if !known {
		return cbor.Value{}, ErrMalformedFrame
	}
	fields, ok := readFields(v, table)
	if !ok || !hasFields(fields, append(required, "version", "frame_type")...) {
		return cbor.Value{}, ErrMalformedFrame
	}
	return v, nil
}

// AdvertiseFrame is macula 12's ADVERTISE: the signed procedure_advertisement
// record, as encoded bytes.
func AdvertiseFrame(advertisement []byte) cbor.Value {
	return cbor.Map(append(base("advertise", freshFrameID(), currentMillis()),
		bytesEntry("advertisement", advertisement)))
}

// UnadvertiseFrame is macula 12's UNADVERTISE: the signed withdrawal record, as
// encoded bytes.
func UnadvertiseFrame(withdrawal []byte) cbor.Value {
	return cbor.Map(append(base("unadvertise", freshFrameID(), currentMillis()),
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
	fields := append(base(frameType, freshFrameID(), currentMillis()), bytesEntry("realm", realm[:]))
	return append(fields, bytesEntry("topic", topic), bytesEntry("subscriber", subscriber[:])), nil
}

// GoodbyeFrame is macula 12's GOODBYE: a reason of at most 256 bytes, and a
// detail of at most 256 bytes of UTF-8, omitted when detail is nil (absent is
// omitted, WIRE_1_0.md section 3.1).
func GoodbyeFrame(reason string, detail []byte) (cbor.Value, error) {
	if err := boundedText("reason", reason, maxGoodbyeReasonBytes); err != nil {
		return cbor.Value{}, err
	}
	fields := append(base("goodbye", freshFrameID(), currentMillis()), textEntry("reason", reason))
	if detail == nil {
		return cbor.Map(fields), nil
	}
	if err := boundedText("detail", string(detail), maxGoodbyeDetailBytes); err != nil {
		return cbor.Value{}, err
	}
	return cbor.Map(append(fields, bytesEntry("detail", detail))), nil
}
